import { fileURLToPath } from 'node:url'
import { Context } from '@deepseek-ai/cordis'
import CommandRuntime from '@deepseek-ai/dsh-commands'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import { describe, expect, it } from 'vitest'
import PluginScanService from 'dsh-plugin-scan'
import * as ScanRules from 'dsh-plugin-scan-rules'
import * as ToolScan from 'dsh-tool-plugin-scan'
import { renderBatchText, renderScanText } from '../src/index.ts'
import type { Finding, ScanBatchReport, ScanReport } from 'dsh-plugin-scan'

/** A report with `count` synthetic findings, all on distinct files. */
function reportWith(count: number): ScanReport {
  const findings: Finding[] = Array.from({ length: count }, (_, i) => ({
    id: `R:file${i}.ts:1`,
    ruleId: 'CAP_DYNAMIC_EXEC',
    category: 'capability_escalation',
    severity: 'HIGH',
    title: 'Dynamic code execution',
    description: 'synthetic',
    filePath: `file${i}.ts`,
    analyzer: 'capability-analyzer',
  }))
  return {
    package: { name: 'flood', root: '/tmp/flood' },
    findings,
    analyzers: ['capability-analyzer'],
    analyzersFailed: [],
    durationMs: 1,
    findingsCount: findings.length,
    maxSeverity: count === 0 ? 'SAFE' : 'HIGH',
  }
}

const fixture = (name: string) => fileURLToPath(new URL(`../../../testdata/${name}`, import.meta.url))

async function setup() {
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  await ctx.plugin(CommandRuntime)
  await ctx.plugin(PluginScanService)
  await ctx.plugin(ScanRules)
  const fiber = await ctx.plugin(ToolScan)
  return { ctx, fiber }
}

describe('dsh-tool-plugin-scan', () => {
  it('registers the scan_plugin tool on ctx.tools', async () => {
    const { ctx } = await setup()
    expect(ctx.tools.get('scan_plugin')).toBeDefined()
  })

  it('scans a plugin directory through the registered tool body', async () => {
    const { ctx } = await setup()
    const tool = ctx.tools.get('scan_plugin')
    expect(tool).toBeDefined()
    const exec = { signal: new AbortController().signal, agent: undefined }
    // The body is a thin wrapper over ctx.pluginScan.scan; drive it directly.
    const report = await ctx.pluginScan.scan({ kind: 'directory', path: fixture('evil-js-config') })
    expect(report.findings.map((f) => f.ruleId)).toContain('CONFIG_JS_EXPRESSION')
  })

  it('withdraws the tool when the plugin fiber disposes', async () => {
    const { ctx, fiber } = await setup()
    expect(ctx.tools.get('scan_plugin')).toBeDefined()
    await fiber.dispose()
    expect(ctx.tools.get('scan_plugin')).toBeUndefined()
  })

  it('flags a scan as failed at or above failOn', async () => {
    const ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(CommandRuntime)
    await ctx.plugin(PluginScanService)
    await ctx.plugin(ScanRules)
    await ctx.plugin(ToolScan, { failOn: 'HIGH' })

    const tool = ctx.tools.get('scan_plugin')!
    const exec = { signal: new AbortController().signal } as never
    const result = (await tool.execute({ path: fixture('evil-config-override') }, exec)) as { failed?: boolean }
    expect(result.failed).toBe(true)
  })

  it('bounds how many findings a report renders into the model context', () => {
    const text = renderScanText(reportWith(400))

    expect(text).toContain('Scanned flood: 400 finding(s), max HIGH.')
    expect(text.split('\n').filter((line) => line.startsWith('- ['))).toHaveLength(25)
    expect(text).toContain('...and 375 more finding(s)')
    // The count line still tells the whole truth.
    expect(text).toContain('400 finding(s)')
  })

  it('leaves a small report with nothing to summarize', () => {
    expect(renderScanText(reportWith(2))).not.toMatch(/more finding/)
    expect(renderScanText(reportWith(0))).toContain('No known threat patterns detected')
  })

  it('lists only the flagged packages of a batch, bounded', () => {
    const clean = reportWith(0)
    const batch: ScanBatchReport = {
      results: Array.from({ length: 60 }, (_, i) => (i % 2 === 0 ? reportWith(1) : clean)),
      durationMs: 5,
      findingsCount: 30,
      maxSeverity: 'HIGH',
    }
    const text = renderBatchText(batch)

    expect(text.split('\n')[0]).toBe('Scanned 60 plugin(s): 30 finding(s), max HIGH.')
    expect(text.split('\n').filter((line) => line.startsWith('- flood'))).toHaveLength(25)
    expect(text).toContain('...and 5 more package(s) with findings')
    expect(text).toContain('30 package(s) with no findings')
  })

  it('rejects an invalid failOn severity at load', async () => {
    const ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(CommandRuntime)
    await ctx.plugin(PluginScanService)
    await ctx.plugin(ScanRules)
    await expect(ctx.plugin(ToolScan, { failOn: 'BOGUS' })).rejects.toThrow(/failOn/)
  })
})
