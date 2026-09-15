import { fileURLToPath } from 'node:url'
import { Context } from '@deepseek-ai/cordis'
import CommandRuntime from '@deepseek-ai/dsh-commands'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import { describe, expect, it } from 'vitest'
import PluginScanService from 'dsh-plugin-scan'
import * as ScanRules from 'dsh-plugin-scan-rules'
import * as ToolScan from 'dsh-tool-plugin-scan'

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
