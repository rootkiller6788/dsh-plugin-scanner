/**
 * Persistent subprocess bridge that adapts an external scan engine onto the
 * `Analyzer` interface. The engine is spawned once and speaks JSON-lines over
 * stdio; the bridge pins the engine version at handshake and bounds each
 * request with a timeout and a max line size — the same bounded, versioned
 * subprocess posture skill-scanner's cel-go helper uses.
 * @module dsh-plugin-scan-bridge/bridge
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { createInterface, type Interface } from 'node:readline'
import { SEVERITIES, type Analyzer, type Finding, type RulePack, type Severity, type ThreatCategory } from 'dsh-plugin-scan'

/** One rule the engine declares at handshake, surfaced in the registry for transparency. */
export interface EngineRule {
  severity: Severity
  category: ThreatCategory
  description: string
}

/** One finding the engine returns for a scan. */
export interface EngineFinding {
  ruleId: string
  title: string
  description: string
  filePath?: string
  line?: number
  snippet?: string
  remediation?: string
  severity?: Severity
  category?: ThreatCategory
}

/** Configuration for the bridge analyzer. */
export interface BridgeConfig {
  /** Executable to spawn (usually `process.execPath` for a JS engine). */
  command: string
  /** Arguments after the command, e.g. the engine script path. */
  args?: string[]
  /** Engine name, used as the analyzer and pack name. */
  engineName: string
  /** Pinned engine version; a handshake mismatch fails the analyzer. */
  engineVersion: string
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number
  /** Max bytes accepted for one protocol line. */
  maxLineBytes?: number
}

interface InitMsg { op: 'init'; version: string }
interface ReadyMsg { op: 'ready'; version: string; rules?: Record<string, EngineRule> }
interface ScanMsg { op: 'scan'; id: number; root: string }
interface FindingsMsg { op: 'findings'; id: number; findings: EngineFinding[] }
interface ErrorMsg { op: 'error'; id: number; error: string }

const DEFAULT_TIMEOUT_MS = 5_000
const DEFAULT_MAX_LINE_BYTES = 1024 * 1024

interface Pending {
  resolve: (findings: Finding[]) => void
  reject: (error: Error) => void
  timer: NodeJS.Timeout
}

/** Coerce an engine severity into the closed set, defaulting to MEDIUM. */
function coerceSeverity(value: string | undefined): Severity {
  return (SEVERITIES as readonly string[]).includes(value ?? '') ? (value as Severity) : 'MEDIUM'
}

/** Adapt an engine finding into the scanner's {@link Finding}. */
function toFinding(finding: EngineFinding, analyzer: string, index: number): Finding {
  return {
    id: `${finding.ruleId}:${finding.filePath ?? ''}:${finding.line ?? index}`,
    ruleId: finding.ruleId,
    category: finding.category ?? 'supply_chain',
    severity: coerceSeverity(finding.severity),
    title: finding.title,
    description: finding.description,
    filePath: finding.filePath,
    line: finding.line,
    snippet: finding.snippet,
    remediation: finding.remediation,
    analyzer,
  }
}

/**
 * A versioned, bounded subprocess engine speaking the JSON-lines protocol:
 * init -> ready, then scan(id, root) -> findings(id, findings) | error(id, error).
 */
export class EngineBridge {
  private proc: ChildProcessWithoutNullStreams | null = null
  private lines: Interface | null = null
  private readonly pending = new Map<number, Pending>()
  private seq = 0
  private ready = false
  private handshake: { resolve: () => void; reject: (error: Error) => void } | null = null
  private rules: Record<string, EngineRule> = {}

  constructor(private readonly config: BridgeConfig) {}

  /** The engine's declared rules, for registration on `ctx.pluginScan`. */
  get rulePack(): RulePack {
    return { name: this.config.engineName, rules: this.rules }
  }

  private ensureStarted(): void {
    if (this.proc !== null && !this.proc.killed) return
    const proc = spawn(this.config.command, this.config.args ?? [], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    this.proc = proc
    this.lines = createInterface({ input: proc.stdout })
    this.lines.on('line', (line) => this.onLine(line))
    proc.on('exit', () => this.fail(new Error('scan engine exited')))
    proc.stderr.on('data', () => {})
  }

  private onLine(line: string): void {
    if (line.length > (this.config.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES)) return
    let message: ReadyMsg | FindingsMsg | ErrorMsg
    try {
      message = JSON.parse(line) as ReadyMsg | FindingsMsg | ErrorMsg
    } catch {
      return
    }
    if (message.op === 'ready') {
      if (message.version !== this.config.engineVersion) {
        this.fail(new Error(`engine version ${message.version} does not match pinned ${this.config.engineVersion}`))
        return
      }
      this.ready = true
      this.rules = message.rules ?? {}
      this.handshake?.resolve()
      this.handshake = null
      return
    }
    const entry = this.pending.get(message.id)
    if (entry === undefined) return
    this.pending.delete(message.id)
    clearTimeout(entry.timer)
    if (message.op === 'error') entry.reject(new Error(message.error))
    else entry.resolve(message.findings.map((finding, index) => toFinding(finding, this.config.engineName, index)))
  }

  private fail(error: Error): void {
    for (const entry of this.pending.values()) {
      clearTimeout(entry.timer)
      entry.reject(error)
    }
    this.pending.clear()
    this.ready = false
    this.handshake?.reject(error)
    this.handshake = null
  }

  /** Perform the versioned handshake, once. @returns the engine's populated rule pack. */
  async init(): Promise<RulePack> {
    if (this.ready) return this.rulePack
    this.ensureStarted()
    const proc = this.proc!
    await new Promise<void>((resolve, reject) => {
      this.handshake = { resolve, reject }
      proc.stdin.write(`${JSON.stringify({ op: 'init', version: this.config.engineVersion } satisfies InitMsg)}\n`)
      setTimeout(() => reject(new Error('engine handshake timed out')), this.config.timeoutMs ?? DEFAULT_TIMEOUT_MS).unref()
    })
    return this.rulePack
  }

  /** Scan one package root, returning the engine's findings. */
  async scan(root: string): Promise<Finding[]> {
    await this.init()
    const proc = this.proc!
    const id = ++this.seq
    const timeoutMs = this.config.timeoutMs ?? DEFAULT_TIMEOUT_MS
    return new Promise<Finding[]>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`engine request ${id} timed out`))
      }, timeoutMs)
      this.pending.set(id, { resolve, reject, timer })
      proc.stdin.write(`${JSON.stringify({ op: 'scan', id, root } satisfies ScanMsg)}\n`)
    })
  }

  /** Kill the engine process. */
  close(): void {
    this.lines?.close()
    this.proc?.kill()
    this.proc = null
    this.ready = false
    this.fail(new Error('scan engine closed'))
  }
}

/** Build an `Analyzer` backed by the bridge, its eager handshake, and its disposer. */
export function makeBridgeAnalyzer(config: BridgeConfig): { analyzer: Analyzer; init: () => Promise<RulePack>; close: () => void } {
  const bridge = new EngineBridge(config)
  const analyzer: Analyzer = {
    name: config.engineName,
    analyze: (input) => bridge.scan(input.pkg.root),
  }
  return { analyzer, init: () => bridge.init(), close: () => bridge.close() }
}
