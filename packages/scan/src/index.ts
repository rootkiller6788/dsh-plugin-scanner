/**
 * Service Definition for the dsh plugin scanner (`ctx.pluginScan`).
 *
 * This is the pluginized core: analyzers and rule packs register through
 * effects (`registerAnalyzer` / `registerRulePack` return disposers), exactly
 * like a Cordis plugin contribution. There is no privileged factory — the
 * built-in analyzers in `dsh-plugin-scan-rules` use the same public methods a
 * third-party detector uses.
 * @module dsh-plugin-scan
 */

import { Service, type Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'

declare module '@deepseek-ai/cordis' {
  interface Context {
    pluginScan: PluginScanService
  }
}

/** Severity levels, highest first. */
export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

/** One severity level. */
export type Severity = (typeof SEVERITIES)[number]

/**
 * Rank of each level, higher is more severe; `SAFE` (a scan with no findings)
 * sits below every real level. Derived from {@link SEVERITIES} so a level
 * inserted into that list re-ranks instead of silently keeping the old order.
 */
export const SEVERITY_RANK: Readonly<Record<Severity | 'SAFE', number>> = Object.freeze(
  // SEVERITIES is exhaustive over `Severity` and `SAFE` is added here, so the map is total.
  Object.fromEntries([
    ...SEVERITIES.map((severity, index) => [severity, SEVERITIES.length - index] as const),
    ['SAFE', 0] as const,
  ]) as Record<Severity | 'SAFE', number>,
)

/** The more severe of two levels. */
export function worstSeverity(a: Severity | 'SAFE', b: Severity | 'SAFE'): Severity | 'SAFE' {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b
}

/** Whether `severity` is at or above `threshold`. */
export function atLeast(severity: Severity | 'SAFE', threshold: Severity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]
}

/** A JSON-safe value; used for finding metadata so reports are model- and wire-safe. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }

/** Threat categories specific to dsh plugins (not skill packages). */
export const THREAT_CATEGORIES = [
  'config_row_override',
  'js_config_expression',
  'capability_escalation',
  'supply_chain',
  'prompt_injection',
  'tool_shadowing',
  'dynamic_package',
  'self_modification',
] as const

/** One threat category. */
export type ThreatCategory = (typeof THREAT_CATEGORIES)[number]

/** A security issue discovered in a scanned plugin package. */
export interface Finding {
  /** Stable identifier (rule id + file + line). */
  readonly id: string
  /** Rule that produced this finding; must have a manifest entry in a registered rule pack. */
  readonly ruleId: string
  readonly category: ThreatCategory
  readonly severity: Severity
  readonly title: string
  readonly description: string
  readonly filePath?: string
  readonly line?: number
  readonly snippet?: string
  readonly remediation?: string
  readonly analyzer: string
  readonly metadata?: Readonly<Record<string, JsonValue>>
}

/** How a scanned file is classified for the analyzers. */
export type PluginFileKind = 'source' | 'config' | 'manifest' | 'markdown' | 'json' | 'other'

/** One file within a scanned plugin package. */
export interface PluginFile {
  /** Path relative to the package root, POSIX-separated. */
  readonly path: string
  readonly content: string
  readonly kind: PluginFileKind
}

/** One resolvable row extracted from a `cordis.patch.yml`. */
export interface CordisRow {
  readonly id: string
  readonly name?: string
  readonly config?: unknown
  readonly disabled?: boolean
}

/** A scanned plugin package: parsed manifest, patch rows, and source files. */
export interface PluginPackage {
  readonly root: string
  readonly name: string
  readonly version?: string
  /** Raw `package.json` text. */
  readonly manifest?: string
  readonly scripts?: Readonly<Record<string, string>>
  readonly dependencies?: Readonly<Record<string, string>>
  readonly patchRows: readonly CordisRow[]
  /** Raw `cordis.patch.yml` text, kept for `!!js` detection that YAML parsing would lose. */
  readonly patchRaw?: string
  readonly files: readonly PluginFile[]
  /** Ephemeral clone root (github target); remove after the scan. */
  readonly tempRoot?: string
}

/** What to scan. `registry` is batch and is handled by `scanRegistry`. */
export type ScanTarget =
  | { readonly kind: 'directory'; readonly path: string }
  | { readonly kind: 'profile'; readonly name: string }
  | { readonly kind: 'registry'; readonly path: string }
  | { readonly kind: 'github'; readonly repo: string }

/** Input handed to one analyzer. */
export interface ScanInput {
  readonly target: ScanTarget
  readonly pkg: PluginPackage
}

/** A detector. Both built-in and third-party analyzers share this interface. */
export interface Analyzer {
  readonly name: string
  analyze(input: ScanInput, signal?: AbortSignal): readonly Finding[] | Promise<readonly Finding[]>
}

/** Manifest metadata for one rule. */
export interface RuleMeta {
  readonly severity: Severity
  readonly category: ThreatCategory
  readonly description: string
}

/** A validated rule-pack manifest: every emitted `ruleId` must have an entry. */
export interface RulePack {
  readonly name: string
  readonly rules: Readonly<Record<string, RuleMeta>>
}

/** Effective scan policy: rules to skip and per-rule severity overrides. */
export interface ScanPolicy {
  readonly disabledRules: ReadonlySet<string>
  readonly severityOverrides: Readonly<Record<string, Severity>>
}

/** One analyzer that failed without aborting the scan. */
export interface AnalyzerFailure {
  readonly analyzer: string
  readonly error: string
}

/** The outcome of a batch scan over several packages (the `registry` target). */
export interface ScanBatchReport {
  readonly results: readonly ScanReport[]
  readonly durationMs: number
  readonly findingsCount: number
  readonly maxSeverity: Severity | 'SAFE'
}

/** The outcome of one scan. */
export interface ScanReport {
  readonly package: { readonly name: string; readonly root: string }
  readonly findings: readonly Finding[]
  readonly analyzers: readonly string[]
  readonly analyzersFailed: readonly AnalyzerFailure[]
  readonly durationMs: number
  readonly findingsCount: number
  readonly maxSeverity: Severity | 'SAFE'
}

/** Plugin configuration for {@link PluginScanService}. */
export interface Config {
  /** Rule ids dropped from every scan. */
  disabledRules?: string[]
  /** Per-rule severity overrides applied after analyzers run. */
  severityOverrides?: Record<string, Severity>
}

/** Render an unknown thrown value as a bounded message. */
function renderThrown(value: unknown): string {
  if (value instanceof Error) return value.message
  try {
    return String(value)
  } catch {
    return 'unknown error'
  }
}

/** Highest severity present, or `SAFE` when there are no findings. */
function maxSeverity(findings: readonly Finding[]): Severity | 'SAFE' {
  let worst: Severity | 'SAFE' = 'SAFE'
  for (const finding of findings) {
    if (SEVERITY_RANK[finding.severity] > SEVERITY_RANK[worst]) worst = finding.severity
  }
  return worst
}

/**
 * The scanner registry (`ctx.pluginScan`).
 *
 * Registers analyzers and rule packs as effects, so disposing the owning fiber
 * withdraws them. `scan()` runs every registered analyzer over a loaded package
 * and applies policy (disabled rules, severity overrides); a failing analyzer
 * is recorded in `analyzersFailed` rather than swallowed.
 */
export class PluginScanService extends Service {
  static inject = []
  static Config: z<Config> = z.object({
    disabledRules: z.array(z.string()).default([]),
    severityOverrides: z.dict(z.union(SEVERITIES)).default({}),
  })

  private readonly analyzers: Analyzer[] = []
  private readonly rulePacks: RulePack[] = []
  private readonly disabledRules: ReadonlySet<string>
  private readonly severityOverrides: Readonly<Record<string, Severity>>

  constructor(ctx: Context, config: Config = {}) {
    super(ctx, 'pluginScan')
    this.disabledRules = new Set(config.disabledRules ?? [])
    this.severityOverrides = { ...config.severityOverrides }
  }

  /** Register a detector. @returns the disposer that withdraws it. */
  registerAnalyzer(analyzer: Analyzer): () => void {
    this.analyzers.push(analyzer)
    return () => {
      const index = this.analyzers.indexOf(analyzer)
      if (index !== -1) this.analyzers.splice(index, 1)
    }
  }

  /** Register a rule-pack manifest used to validate emitted rule ids. @returns the disposer. */
  registerRulePack(pack: RulePack): () => void {
    this.rulePacks.push(pack)
    return () => {
      const index = this.rulePacks.indexOf(pack)
      if (index !== -1) this.rulePacks.splice(index, 1)
    }
  }

  /** The effective policy this service is configured with. */
  get policy(): ScanPolicy {
    return { disabledRules: this.disabledRules, severityOverrides: this.severityOverrides }
  }

  /** The combined manifest across registered rule packs. */
  get ruleRegistry(): Readonly<Record<string, RuleMeta>> {
    const merged: Record<string, RuleMeta> = {}
    for (const pack of this.rulePacks) Object.assign(merged, pack.rules)
    return merged
  }

  /**
   * Scan one target package.
   * @param target - directory (v1) or a reserved profile/registry/github target.
   * @param options - optional cancellation signal.
   * @returns the policy-normalized report.
   */
  async scan(target: ScanTarget, options?: { signal?: AbortSignal }): Promise<ScanReport> {
    const start = Date.now()
    const { loadPluginPackage, cleanupPackage } = await import('./load.ts')
    const pkg = loadPluginPackage(target)

    try {
      const findings: Finding[] = []
      const analyzers: string[] = []
      const analyzersFailed: AnalyzerFailure[] = []
      for (const analyzer of this.analyzers) {
        analyzers.push(analyzer.name)
        try {
          const found = await analyzer.analyze({ target, pkg }, options?.signal)
          findings.push(...found)
        } catch (error) {
          analyzersFailed.push({ analyzer: analyzer.name, error: renderThrown(error) })
        }
      }

      const normalized = this.applyPolicy(findings)
      return {
        package: { name: pkg.name, root: pkg.root },
        findings: normalized,
        analyzers,
        analyzersFailed,
        durationMs: Date.now() - start,
        findingsCount: normalized.length,
        maxSeverity: maxSeverity(normalized),
      }
    } finally {
      cleanupPackage(pkg)
    }
  }

  /**
   * Scan every package listed in a registry file (a JSON array of
   * `{ name, path? }` or `{ name, repo? }` entries), aggregating the results.
   * @param path - path to the registry JSON file.
   * @param options - optional cancellation signal.
   * @returns the aggregate batch report.
   */
  async scanRegistry(path: string, options?: { signal?: AbortSignal }): Promise<ScanBatchReport> {
    const start = Date.now()
    const { readRegistryTargets } = await import('./load.ts')
    const targets = readRegistryTargets(path)

    const results: ScanReport[] = []
    for (const target of targets) {
      results.push(await this.scan(target, options))
    }

    return {
      results,
      durationMs: Date.now() - start,
      findingsCount: results.reduce((sum, result) => sum + result.findingsCount, 0),
      // Each result already ranked its own findings; folding the maxima avoids
      // materializing every finding of the batch just to rank it again.
      maxSeverity: results.reduce<Severity | 'SAFE'>((worst, result) => worstSeverity(worst, result.maxSeverity), 'SAFE'),
    }
  }

  private applyPolicy(findings: readonly Finding[]): Finding[] {
    const out: Finding[] = []
    for (const finding of findings) {
      if (this.disabledRules.has(finding.ruleId)) continue
      const override = this.severityOverrides[finding.ruleId]
      if (override !== undefined && override !== finding.severity) {
        out.push({ ...finding, severity: override, metadata: { ...finding.metadata, policySeverityOverride: override } })
      } else {
        out.push(finding)
      }
    }
    return out
  }
}

export default PluginScanService
