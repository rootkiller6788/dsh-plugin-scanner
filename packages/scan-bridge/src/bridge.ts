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
/**
 * How much of the engine's stderr to keep for a failure message. The head, not
 * the tail: a crash states its reason first and spends the rest on a trace.
 */
const MAX_STDERR_CHARS = 1024

/** Attach the engine's last words to a failure reason, if it left any. */
function withStderr(reason: string, stderr: string): string {
  const tail = stderr.trim().replace(/\s+/gu, ' ')
  return tail.length === 0 ? reason : `${reason}: ${tail}`
}

interface Pending {
  resolve: (findings: Finding[]) => void
  reject: (error: Error) => void
  timer: NodeJS.Timeout
}

/** The single in-flight (or completed) handshake, shared by every caller. */
interface Handshake {
  promise: Promise<RulePack>
  resolve: (pack: RulePack) => void
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
  /** The current engine's stderr, bounded, for failure messages. */
  private stderr = ''
  private seq = 0
  private ready = false
  private handshake: Handshake | null = null
  /**
   * The engine's declared rules, mutated in place on every handshake so the
   * {@link rulePack} object a consumer already registered stays live across an
   * engine restart instead of freezing the first handshake's snapshot.
   */
  private readonly rules: Record<string, EngineRule> = {}

  constructor(private readonly config: BridgeConfig) {}

  /** The engine's declared rules, for registration on `ctx.pluginScan`. */
  get rulePack(): RulePack {
    return { name: this.config.engineName, rules: this.rules }
  }

  private ensureStarted(): void {
    if (this.proc !== null) return
    const proc = spawn(this.config.command, this.config.args ?? [], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    this.proc = proc
    this.lines = createInterface({ input: proc.stdout })
    this.lines.on('line', (line) => this.onLine(line))
    // 'close' rather than 'exit': it fires once stdio is drained, so anything
    // the engine wrote to stderr is available when the failure is reported.
    proc.on('close', () => this.onEngineGone('scan engine exited'))
    // Without a listener a spawn failure is an uncaught 'error' event that takes
    // the host process down; it belongs on the handshake, not on the stack.
    proc.on('error', (error: Error) => this.fail(new Error(`scan engine failed to start: ${error.message}`)))
    // Same for a write to a process that already died: EPIPE would otherwise
    // surface as an uncaught exception instead of a failed request.
    proc.stdin.on('error', (error: Error) => this.fail(new Error(`scan engine stdin failed: ${error.message}`)))
    proc.stderr.on('data', (chunk: Buffer) => {
      if (this.stderr.length >= MAX_STDERR_CHARS) return
      this.stderr = (this.stderr + chunk.toString('utf8')).slice(0, MAX_STDERR_CHARS)
    })
  }

  /**
   * Drop the dead engine's process state. Clearing `proc` is what lets
   * {@link ensureStarted} spawn a replacement: a child that exits on its own
   * never sets `killed`, so keying the "already started" check on `killed`
   * left every later request writing into a dead process and timing out.
   */
  private onEngineGone(reason: string): void {
    this.lines?.close()
    this.lines = null
    this.proc = null
    this.setRules({})
    const stderr = this.stderr
    this.stderr = ''
    this.fail(new Error(withStderr(reason, stderr)))
  }

  /** Replace the declared rule set, keeping the published object identity. */
  private setRules(rules: Record<string, EngineRule>): void {
    for (const ruleId of Object.keys(this.rules)) delete this.rules[ruleId]
    Object.assign(this.rules, rules)
  }

  /**
   * Settle the in-flight handshake, if any. Every path that can end a
   * handshake (a `ready` line, the timeout, or a failure) goes through here,
   * so the field is cleared exactly once and the timer never outlives it.
   */
  private finishHandshake(outcome: { pack: RulePack } | { error: Error }): void {
    const handshake = this.handshake
    if (handshake === null) return
    this.handshake = null
    clearTimeout(handshake.timer)
    if ('pack' in outcome) handshake.resolve(outcome.pack)
    else handshake.reject(outcome.error)
  }

  /** Spawn the engine if needed and send `init`, registering the one handshake. */
  private startHandshake(): Handshake {
    this.ensureStarted()
    const proc = this.proc
    if (proc === null) throw new Error('scan engine failed to start')
    const timeoutMs = this.config.timeoutMs ?? DEFAULT_TIMEOUT_MS
    let resolve!: (pack: RulePack) => void
    let reject!: (error: Error) => void
    const promise = new Promise<RulePack>((res, rej) => {
      resolve = res
      reject = rej
    })
    const handshake: Handshake = {
      promise,
      resolve,
      reject,
      timer: setTimeout(() => {
        this.finishHandshake({ error: new Error(`engine handshake timed out after ${timeoutMs}ms`) })
      }, timeoutMs),
    }
    handshake.timer.unref()
    // Registered before the write: a `ready` arriving early must find something
    // to settle.
    this.handshake = handshake
    proc.stdin.write(`${JSON.stringify({ op: 'init', version: this.config.engineVersion } satisfies InitMsg)}\n`)
    return handshake
  }

  private onLine(line: string): void {
    // `maxLineBytes` is bytes: measuring `line.length` counts UTF-16 units, so a
    // line of multi-byte text would slip through at up to 4x the stated cap.
    const maxLineBytes = this.config.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES
    if (Buffer.byteLength(line, 'utf8') > maxLineBytes) {
      // Dropping the line silently leaves its request waiting out the full
      // timeout and reports "request N timed out"; once a line is dropped the
      // framing cannot be trusted either, so fail the in-flight requests.
      this.fail(new Error(`scan engine line exceeds the ${maxLineBytes}-byte cap`))
      return
    }
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
      this.setRules(message.rules ?? {})
      this.finishHandshake({ pack: this.rulePack })
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
    this.finishHandshake({ error })
  }

  /**
   * Perform the versioned handshake, once. Concurrent callers share the one
   * in-flight handshake — a second `init` must not overwrite the promise the
   * first caller is awaiting.
   * @returns the engine's populated rule pack.
   */
  async init(): Promise<RulePack> {
    if (this.ready) return this.rulePack
    return (this.handshake ?? this.startHandshake()).promise
  }

  /** Scan one package root, returning the engine's findings. */
  async scan(root: string): Promise<Finding[]> {
    await this.init()
    // The engine can die between a successful handshake and this line.
    const proc = this.proc
    if (proc === null) throw new Error('scan engine is not running')
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
    const proc = this.proc
    this.lines?.close()
    this.lines = null
    this.proc = null
    this.ready = false
    this.setRules({})
    this.fail(new Error('scan engine closed'))
    proc?.kill()
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
