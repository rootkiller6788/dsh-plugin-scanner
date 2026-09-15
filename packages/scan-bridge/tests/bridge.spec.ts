import { fileURLToPath } from 'node:url'
import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it } from 'vitest'
import PluginScanService from 'dsh-plugin-scan'
import * as ScanBridge from 'dsh-plugin-scan-bridge'
import { EngineBridge } from '../src/bridge.ts'

const fixture = (name: string) => fileURLToPath(new URL(`../../../testdata/${name}`, import.meta.url))
const engine = fileURLToPath(new URL('../../../testdata/engine/engine.mjs', import.meta.url))
const crashEngine = fileURLToPath(new URL('../../../testdata/engine/crash-engine.mjs', import.meta.url))

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

function config(overrides: Partial<ScanBridge.Config> = {}): ScanBridge.Config {
  return {
    command: process.execPath,
    args: [engine],
    engineName: 'fixture-engine',
    engineVersion: '1.0.0',
    ...overrides,
  }
}

async function scanWith(cfg: ScanBridge.Config, target: string) {
  const ctx = new Context()
  await ctx.plugin(PluginScanService)
  await ctx.plugin(ScanBridge, cfg)
  return ctx.pluginScan.scan({ kind: 'directory', path: target })
}

describe('dsh-plugin-scan-bridge', () => {
  it('adds an external engine as an analyzer through registerAnalyzer', async () => {
    const report = await scanWith(config(), fixture('evil-js-config'))
    expect(report.analyzers).toContain('fixture-engine')
    expect(report.findings.map((f) => f.ruleId)).toContain('ENGINE_EVIL')
  })

  it('returns no findings for a clean package', async () => {
    const report = await scanWith(config(), fixture('clean-plugin'))
    expect(report.findings.map((f) => f.ruleId)).not.toContain('ENGINE_EVIL')
  })

  it('shares one handshake between scans that start together', async () => {
    // Both scans reach init() before the engine is ready. A second handshake
    // must not replace the promise the first caller is awaiting, or that caller
    // waits on a promise nothing will ever settle.
    const bridge = new EngineBridge(config())
    try {
      const root = fixture('evil-js-config')
      const [a, b] = await Promise.all([bridge.scan(root), bridge.scan(root)])
      expect(a.map((f) => f.ruleId)).toContain('ENGINE_EVIL')
      expect(b.map((f) => f.ruleId)).toContain('ENGINE_EVIL')
    } finally {
      bridge.close()
    }
  })

  it('registers the engine rule pack for transparency', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    await ctx.plugin(ScanBridge, config())
    expect(ctx.pluginScan.ruleRegistry.ENGINE_EVIL?.severity).toBe('HIGH')
  })

  it('rejects plugin load on a version mismatch', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    await expect(ctx.plugin(ScanBridge, config({ engineVersion: '9.9.9' }))).rejects.toThrow(/version/)
  })

  /** Load the crashing engine (`--mode=after-scan`) and scan one evil fixture. */
  async function scanWithCrashEngine() {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    await ctx.plugin(ScanBridge, config({
      args: [crashEngine, '--mode=after-scan'],
      engineName: 'crash-engine',
      timeoutMs: 3_000,
    }))
    const target = { kind: 'directory', path: fixture('evil-js-config') } as const
    const first = await ctx.pluginScan.scan(target)
    expect(first.findings.map((f) => f.ruleId)).toContain('CRASH_ENGINE')
    await delay(300) // let the engine's exit be observed
    return { ctx, target }
  }

  it('withdraws the engine rules once the engine is gone', async () => {
    const { ctx } = await scanWithCrashEngine()
    // Rules declared by a dead engine are no longer backed by anything.
    expect(ctx.pluginScan.ruleRegistry.CRASH_ENGINE).toBeUndefined()
  })

  it('respawns an engine that exited instead of writing into the corpse', async () => {
    const { ctx, target } = await scanWithCrashEngine()

    const second = await ctx.pluginScan.scan(target)
    expect(second.analyzersFailed).toEqual([])
    expect(second.findings.map((f) => f.ruleId)).toContain('CRASH_ENGINE')
    expect(ctx.pluginScan.ruleRegistry.CRASH_ENGINE).toBeDefined()
  })

  it('closes the engine and withdraws the analyzer on dispose', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const fiber = await ctx.plugin(ScanBridge, config())
    expect(ctx.pluginScan.ruleRegistry.ENGINE_EVIL).toBeDefined()

    await fiber.dispose()
    const after = await ctx.pluginScan.scan({ kind: 'directory', path: fixture('evil-js-config') })
    expect(after.analyzers).not.toContain('fixture-engine')
    expect(ctx.pluginScan.ruleRegistry.ENGINE_EVIL).toBeUndefined()
  })
})
