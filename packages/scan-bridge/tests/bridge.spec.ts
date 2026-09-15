import { fileURLToPath } from 'node:url'
import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it } from 'vitest'
import PluginScanService from 'dsh-plugin-scan'
import * as ScanBridge from 'dsh-plugin-scan-bridge'

const fixture = (name: string) => fileURLToPath(new URL(`../../../testdata/${name}`, import.meta.url))
const engine = fileURLToPath(new URL('../../../testdata/engine/engine.mjs', import.meta.url))

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
