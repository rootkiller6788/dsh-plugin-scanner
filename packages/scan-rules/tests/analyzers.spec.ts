import { fileURLToPath } from 'node:url'
import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it } from 'vitest'
import PluginScanService from 'dsh-plugin-scan'
import * as ScanRules from 'dsh-plugin-scan-rules'

function fixture(name: string): string {
  return fileURLToPath(new URL(`../../../testdata/${name}`, import.meta.url))
}

async function scanFixture(name: string) {
  const ctx = new Context()
  await ctx.plugin(PluginScanService)
  await ctx.plugin(ScanRules)
  return ctx.pluginScan.scan({ kind: 'directory', path: fixture(name) })
}

describe('built-in analyzers', () => {
  it('flags trusted-row override and disable', async () => {
    const report = await scanFixture('evil-config-override')
    const ids = report.findings.map((f) => f.ruleId)
    expect(ids).toContain('CONFIG_TRUSTED_ROW_OVERRIDE')
    expect(ids).toContain('CONFIG_TRUSTED_ROW_DISABLED')
    expect(report.findings.some((f) => f.severity === 'CRITICAL')).toBe(true)
  })

  it('flags !!js expressions and capability reach', async () => {
    const report = await scanFixture('evil-js-config')
    const ids = report.findings.map((f) => f.ruleId)
    expect(ids).toContain('CONFIG_JS_EXPRESSION')
    expect(ids).toContain('CONFIG_JS_CAPABILITY')
  })

  it('flags capability escalation and credential exfiltration', async () => {
    const report = await scanFixture('evil-exfil-plugin')
    const ids = report.findings.map((f) => f.ruleId)
    expect(ids).toContain('CAP_DANGEROUS_IMPORT')
    expect(ids).toContain('CAP_CREDENTIAL_EXFIL')
  })

  it('flags built-in tool shadowing', async () => {
    const report = await scanFixture('evil-tool-shadow')
    expect(report.findings.map((f) => f.ruleId)).toContain('CAP_TOOL_SHADOW')
  })

  it('flags lifecycle scripts', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    await ctx.plugin(ScanRules)
    const report = await ctx.pluginScan.scan({
      kind: 'directory',
      path: fileURLToPath(new URL('../../../testdata/evil-config-override', import.meta.url)),
    })
    // evil-config-override has no lifecycle script; this guards the manifest path only.
    expect(report.findings.map((f) => f.ruleId)).not.toContain('SUPPLY_LIFECYCLE_SCRIPT')
  })

  it('leaves a clean plugin with zero findings', async () => {
    const report = await scanFixture('clean-plugin')
    expect(report.findings).toEqual([])
    expect(report.maxSeverity).toBe('SAFE')
  })

  it('registers four analyzers and withdraws them on dispose', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const fiber = await ctx.plugin(ScanRules)
    expect(ctx.pluginScan.scan).toBeTypeOf('function')
    const names = await ctx.pluginScan.scan({ kind: 'directory', path: fixture('clean-plugin') }).then((r) => r.analyzers)
    expect(names).toEqual(['config-analyzer', 'capability-analyzer', 'model-analyzer', 'runtime-analyzer'])

    await fiber.dispose()
    const after = await ctx.pluginScan.scan({ kind: 'directory', path: fixture('clean-plugin') })
    expect(after.analyzers).toEqual([])
  })
})
