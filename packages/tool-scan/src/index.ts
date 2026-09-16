/**
 * Consumer for the plugin scanner: a model-facing `scan_plugin` tool and a
 * human-facing `/scan` command over `ctx.pluginScan`. Report-only in v1 — the
 * tool returns a structured report and never blocks the model on a finding.
 * @module dsh-tool-plugin-scan
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-tools'
import { SEVERITIES, atLeast, type ScanBatchReport, type ScanReport, type ScanTarget, type Severity } from 'dsh-plugin-scan'

/** Cordis plugin name. */
export const name = 'tool-plugin-scan'

/** Services this consumer reads: the scanner, the tool registry, and the command registry. */
export const inject = ['pluginScan', 'tools', 'commands']

export interface Config {
  /** Severity at or above which the report is flagged `failed`. Empty disables. */
  failOn?: string
}

export const Config: z<Config> = z.object({
  failOn: z.string().default(''),
})

/** Parse and validate `failOn`; `''` disables the threshold. */
function parseFailOn(value: string): Severity | undefined {
  if (value === '') return undefined
  if (!(SEVERITIES as readonly string[]).includes(value)) {
    throw new Error(`invalid failOn severity "${value}"; expected one of ${SEVERITIES.join(', ')}`)
  }
  return value as Severity
}

/**
 * How many findings / packages a rendered report spells out before it
 * summarizes. `output.render` returns the model-facing content blocks
 * (`ToolResult.content`), so this text is what a hostile package would be
 * flooding if it could print one line per file it shipped.
 */
const MAX_RENDERED_FINDINGS = 25
const MAX_RENDERED_PACKAGES = 25

/**
 * Render a batch report as one text block. Only the packages with findings are
 * listed — in a registry of a thousand entries the clean ones are the noise.
 */
export function renderBatchText(batch: ScanBatchReport): string {
  const flagged = batch.results.filter((result) => result.findingsCount > 0)
  const lines = [`Scanned ${batch.results.length} plugin(s): ${batch.findingsCount} finding(s), max ${batch.maxSeverity}.`]
  for (const result of flagged.slice(0, MAX_RENDERED_PACKAGES)) {
    lines.push(`- ${result.package.name}: ${result.findingsCount} finding(s), max ${result.maxSeverity}`)
  }
  const hidden = flagged.length - MAX_RENDERED_PACKAGES
  if (hidden > 0) lines.push(`- ...and ${hidden} more package(s) with findings`)
  lines.push(`- ${batch.results.length - flagged.length} package(s) with no findings`)
  return lines.join('\n')
}

/** Render a report as one text block, bounded so findings cannot flood the context. */
export function renderScanText(report: ScanReport & { failed?: boolean }): string {
  const lines: string[] = []
  lines.push(`Scanned ${report.package.name}: ${report.findingsCount} finding(s), max ${report.maxSeverity}.`)
  for (const finding of report.findings.slice(0, MAX_RENDERED_FINDINGS)) {
    const where = finding.filePath !== undefined ? ` @ ${finding.filePath}` : ''
    lines.push(`- [${finding.severity}] ${finding.title} (${finding.ruleId})${where}`)
  }
  const hidden = report.findings.length - MAX_RENDERED_FINDINGS
  if (hidden > 0) {
    lines.push(`- ...and ${hidden} more finding(s); the report object carries every one.`)
  }
  for (const failure of report.analyzersFailed) {
    lines.push(`- analyzer ${failure.analyzer} failed: ${failure.error}`)
  }
  if (report.findingsCount === 0) {
    lines.push('No known threat patterns detected. This does not guarantee the plugin is safe.')
  }
  if (report.failed === true) {
    lines.push('FAILED: findings reach the configured failOn threshold.')
  }
  return lines.join('\n')
}

/** Register the `scan_plugin` tool and the `/scan` command. */
export function apply(ctx: Context, config: Config = {}): void {
  const failOn = parseFailOn(config.failOn ?? '')

  ctx.tools.register(defineTool({
    name: 'scan_plugin',
    description:
      'Scan a dsh plugin package directory for security risks: config row overrides, !!js expressions, capability escalation, prompt injection, and self-modification.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path to the plugin package directory.' },
    },
    output: {
      schema: { type: 'json' },
      render: (_args, value) => [{ type: 'text', text: renderScanText(value as unknown as ScanReport & { failed?: boolean }) }],
    },
    async execute(args, exec) {
      const target: ScanTarget = { kind: 'directory', path: args.path }
      const report = await ctx.pluginScan.scan(target, { signal: exec.signal })
      const failed = failOn !== undefined && atLeast(report.maxSeverity, failOn)
      // The report is JSON-safe by construction; the cast satisfies the `json` output schema.
      return { ...report, failed } as unknown as JsonValue
    },
    presentCall: (args) => ({
      card: 'generic',
      title: `Scan plugin ${args.path}`,
      kind: 'search',
      locations: [{ path: args.path }],
    }),
  }))

  ctx.commands.register({
    name: 'scan',
    description: 'scan a dsh plugin package directory for security risks',
    input: { hint: '<path>' },
    handler: async (invocation) => {
      const path = invocation.rawInput.trim()
      if (path.length === 0) return { kind: 'error', text: 'Usage: /scan <plugin-directory-path>' }
      try {
        const report = await ctx.pluginScan.scan({ kind: 'directory', path }, { signal: invocation.signal })
        const failed = failOn !== undefined && atLeast(report.maxSeverity, failOn)
        return { kind: 'success', text: renderScanText({ ...report, failed }) }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        return { kind: 'error', text: `scan failed: ${message}` }
      }
    },
  })

  ctx.commands.register({
    name: 'scan-registry',
    description: 'scan every plugin listed in a registry JSON file',
    input: { hint: '<registry.json path>' },
    handler: async (invocation) => {
      const path = invocation.rawInput.trim()
      if (path.length === 0) return { kind: 'error', text: 'Usage: /scan-registry <registry.json path>' }
      try {
        const batch = await ctx.pluginScan.scanRegistry(path, { signal: invocation.signal })
        return { kind: 'success', text: renderBatchText(batch) }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        return { kind: 'error', text: `scan-registry failed: ${message}` }
      }
    },
  })
}
