import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it } from 'vitest'
import PluginScanService, { SEVERITIES, SEVERITY_RANK, atLeast, worstSeverity } from '../src/index.ts'
import { loadPluginPackage } from '../src/load.ts'
import type { Analyzer, Config, Finding, RulePack, Severity } from '../src/index.ts'

function fixturePackage(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-scan-'))
  for (const [path, content] of Object.entries(files)) {
    const abs = join(dir, path)
    mkdirSync(join(abs, '..'), { recursive: true })
    writeFileSync(abs, content)
  }
  return dir
}

const fakeFinding = (ruleId: string, analyzer = 'fake'): Finding => ({
  id: `${ruleId}-1`,
  ruleId,
  category: 'capability_escalation',
  severity: 'HIGH',
  title: ruleId,
  description: 'synthetic',
  analyzer,
})

function makeGitRepo(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-repo-'))
  execFileSync('git', ['init', '-q'], { cwd: dir })
  execFileSync('git', ['config', 'user.email', 't@example.com'], { cwd: dir })
  execFileSync('git', ['config', 'user.name', 't'], { cwd: dir })
  for (const [path, content] of Object.entries(files)) {
    const abs = join(dir, path)
    mkdirSync(join(abs, '..'), { recursive: true })
    writeFileSync(abs, content)
  }
  execFileSync('git', ['add', '-A'], { cwd: dir })
  execFileSync('git', ['commit', '-qm', 'init'], { cwd: dir })
  return dir
}

describe('severity ranking', () => {
  it('ranks every level off the SEVERITIES list, with SAFE below all of them', () => {
    expect(SEVERITIES.map((severity) => SEVERITY_RANK[severity])).toEqual([5, 4, 3, 2, 1])
    expect(SEVERITY_RANK.SAFE).toBe(0)
  })

  it('picks the worse of two levels', () => {
    expect(worstSeverity('LOW', 'CRITICAL')).toBe('CRITICAL')
    expect(worstSeverity('CRITICAL', 'LOW')).toBe('CRITICAL')
    expect(worstSeverity('SAFE', 'INFO')).toBe('INFO')
    expect(worstSeverity('SAFE', 'SAFE')).toBe('SAFE')
  })

  it('compares a level against a threshold, SAFE failing every one', () => {
    expect(atLeast('HIGH', 'HIGH')).toBe(true)
    expect(atLeast('CRITICAL', 'HIGH')).toBe(true)
    expect(atLeast('MEDIUM', 'HIGH')).toBe(false)
    expect(atLeast('SAFE', 'INFO')).toBe(false)
  })
})

describe('loadPluginPackage', () => {
  it('defers reading file content until an analyzer asks for it', () => {
    const dir = fixturePackage({ 'a.ts': 'const first = 1', 'data/blob.json': '{"v":1}', 'README.md': '# hi' })
    const pkg = loadPluginPackage({ kind: 'directory', path: dir })

    // The walk classified every entry by path alone; no bytes were read yet.
    expect(Object.fromEntries(pkg.files.map((f) => [f.path, f.kind]))).toEqual({
      'a.ts': 'source',
      'data/blob.json': 'json',
      'README.md': 'markdown',
    })

    // Rewriting the file after the walk proves the content had not been read.
    writeFileSync(join(dir, 'a.ts'), 'const rewritten = 2')
    const entry = pkg.files.find((f) => f.path === 'a.ts')!
    expect(entry.content).toBe('const rewritten = 2')

    // ...and the read is memoized, so a second access does not re-read.
    writeFileSync(join(dir, 'a.ts'), 'const third = 3')
    expect(entry.content).toBe('const rewritten = 2')
  })
})

describe('PluginScanService', () => {
  it('runs a registered analyzer and reports its findings', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const analyzer: Analyzer = { name: 'fake', analyze: () => [fakeFinding('EVIL')] }
    ctx.pluginScan.registerAnalyzer(analyzer)

    const dir = fixturePackage({ 'package.json': JSON.stringify({ name: 'evil' }) })
    const report = await ctx.pluginScan.scan({ kind: 'directory', path: dir })

    expect(report.analyzers).toEqual(['fake'])
    expect(report.findingsCount).toBe(1)
    expect(report.maxSeverity).toBe('HIGH')
    expect(report.findings[0]!.ruleId).toBe('EVIL')
  })

  it('withdraws an analyzer when its disposer runs', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const analyzer: Analyzer = { name: 'fake', analyze: () => [fakeFinding('EVIL')] }
    const dispose = ctx.pluginScan.registerAnalyzer(analyzer)

    const dir = fixturePackage({ 'package.json': JSON.stringify({ name: 'evil' }) })
    expect((await ctx.pluginScan.scan({ kind: 'directory', path: dir })).findingsCount).toBe(1)

    dispose()
    expect((await ctx.pluginScan.scan({ kind: 'directory', path: dir })).findingsCount).toBe(0)
  })

  it('runs the registered analyzers together, reporting them in registration order', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const order: string[] = []
    let release: () => void = () => {}
    const gate = new Promise<void>((resolve) => { release = resolve })
    const slow: Analyzer = {
      name: 'slow',
      analyze: async () => {
        order.push('slow:start')
        await gate
        order.push('slow:end')
        return [fakeFinding('SLOW', 'slow')]
      },
    }
    const fast: Analyzer = {
      name: 'fast',
      analyze: () => {
        order.push('fast:start')
        return [fakeFinding('FAST', 'fast')]
      },
    }
    ctx.pluginScan.registerAnalyzer(slow)
    ctx.pluginScan.registerAnalyzer(fast)

    const dir = fixturePackage({ 'package.json': JSON.stringify({ name: 'pkg' }) })
    const pending = ctx.pluginScan.scan({ kind: 'directory', path: dir })
    await new Promise((resolve) => setTimeout(resolve, 0))

    // `fast` started while `slow` was still parked — the two were not serialized.
    expect(order).toEqual(['slow:start', 'fast:start'])

    release()
    const report = await pending
    // Concurrency does not reorder the report.
    expect(report.analyzers).toEqual(['slow', 'fast'])
    expect(report.findings.map((f) => f.ruleId)).toEqual(['SLOW', 'FAST'])
  })

  it('records an analyzer failure without aborting the scan', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const good: Analyzer = { name: 'good', analyze: () => [fakeFinding('EVIL', 'good')] }
    const bad: Analyzer = { name: 'bad', analyze: () => { throw new Error('boom') } }
    ctx.pluginScan.registerAnalyzer(good)
    ctx.pluginScan.registerAnalyzer(bad)

    const dir = fixturePackage({ 'package.json': JSON.stringify({ name: 'evil' }) })
    const report = await ctx.pluginScan.scan({ kind: 'directory', path: dir })

    expect(report.findingsCount).toBe(1)
    expect(report.analyzersFailed).toEqual([{ analyzer: 'bad', error: 'boom' }])
  })

  it('applies disabledRules and severityOverrides from config', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService, { disabledRules: ['DROP_ME'], severityOverrides: { DEMOTE: 'LOW' } })
    const analyzer: Analyzer = { name: 'fake', analyze: () => [fakeFinding('DROP_ME'), fakeFinding('DEMOTE'), fakeFinding('KEEP')] }
    ctx.pluginScan.registerAnalyzer(analyzer)

    const dir = fixturePackage({ 'package.json': JSON.stringify({ name: 'evil' }) })
    const report = await ctx.pluginScan.scan({ kind: 'directory', path: dir })

    expect(report.findings.map((f) => f.ruleId)).toEqual(['DEMOTE', 'KEEP'])
    expect(report.findings[0]!.severity).toBe('LOW')
    expect(report.findings[0]!.metadata?.policySeverityOverride).toBe('LOW')
  })

  it('rejects a registry target in the single-package scan method', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    await expect(ctx.pluginScan.scan({ kind: 'registry', path: 'some.json' })).rejects.toThrow(/scanRegistry/)
  })

  it('exposes the merged rule registry from registered packs', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const pack: RulePack = { name: 'core', rules: { EVIL: { severity: 'HIGH', category: 'capability_escalation', description: 'd' } } }
    ctx.pluginScan.registerRulePack(pack)
    expect(ctx.pluginScan.ruleRegistry.EVIL?.severity).toBe('HIGH')
  })

  it('rejects an invalid severity override at load time', async () => {
    const ctx = new Context()
    // Untrusted config crosses a runtime boundary, so the bad value bypasses the type system.
    const bad = { severityOverrides: { EVIL: 'BOGUS' } } as unknown as Config
    await expect(ctx.plugin(PluginScanService, bad)).rejects.toThrow()
  })

  it('scans a profile target by resolving $DSH_HOME/profiles/<name>', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const analyzer: Analyzer = { name: 'fake', analyze: () => [fakeFinding('EVIL')] }
    ctx.pluginScan.registerAnalyzer(analyzer)

    const base = mkdtempSync(join(tmpdir(), 'dsh-home-'))
    const profileDir = join(base, 'profiles', 'web')
    mkdirSync(profileDir, { recursive: true })
    writeFileSync(join(profileDir, 'package.json'), JSON.stringify({ name: 'web' }))
    const prev = process.env.DSH_HOME
    process.env.DSH_HOME = base
    try {
      const report = await ctx.pluginScan.scan({ kind: 'profile', name: 'web' })
      expect(report.package.name).toBe('web')
      expect(report.findingsCount).toBe(1)
    } finally {
      if (prev === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = prev
    }
  })

  it('scans a github target by shallow-cloning a repo', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const analyzer: Analyzer = { name: 'fake', analyze: () => [fakeFinding('EVIL')] }
    ctx.pluginScan.registerAnalyzer(analyzer)

    const repo = makeGitRepo({ 'package.json': JSON.stringify({ name: 'evil-repo' }) })
    const report = await ctx.pluginScan.scan({ kind: 'github', repo })
    expect(report.package.name).toBe('evil-repo')
    expect(report.findingsCount).toBe(1)
  })

  it('scans a registry of plugins in batch', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const analyzer: Analyzer = { name: 'fake', analyze: (input) => (input.pkg.name.includes('evil') ? [fakeFinding('EVIL')] : []) }
    ctx.pluginScan.registerAnalyzer(analyzer)

    const evil = fixturePackage({ 'package.json': JSON.stringify({ name: 'evil-a' }) })
    const clean = fixturePackage({ 'package.json': JSON.stringify({ name: 'clean-a' }) })
    const registryPath = join(mkdtempSync(join(tmpdir(), 'dsh-reg-')), 'registry.json')
    writeFileSync(registryPath, JSON.stringify([
      { name: 'evil-a', path: evil },
      { name: 'clean-a', path: clean },
    ]))

    const batch = await ctx.pluginScan.scanRegistry(registryPath)
    expect(batch.results.length).toBe(2)
    expect(batch.findingsCount).toBe(1)
    expect(batch.maxSeverity).toBe('HIGH')
  })

  it('aggregates the batch maximum from the per-result maxima', async () => {
    const ctx = new Context()
    await ctx.plugin(PluginScanService)
    const byName: Record<string, Severity> = { 'p-crit': 'CRITICAL', 'p-low': 'LOW' }
    const analyzer: Analyzer = {
      name: 'fake',
      analyze: (input) => {
        const severity = byName[input.pkg.name]
        return severity === undefined ? [] : [{ ...fakeFinding('X'), severity }]
      },
    }
    ctx.pluginScan.registerAnalyzer(analyzer)

    const registryPath = join(mkdtempSync(join(tmpdir(), 'dsh-reg-')), 'registry.json')
    writeFileSync(registryPath, JSON.stringify(['p-crit', 'p-low', 'p-clean'].map((name) => ({
      name,
      path: fixturePackage({ 'package.json': JSON.stringify({ name }) }),
    }))))

    const batch = await ctx.pluginScan.scanRegistry(registryPath)
    expect(batch.results.map((result) => result.maxSeverity)).toEqual(['CRITICAL', 'LOW', 'SAFE'])
    expect(batch.maxSeverity).toBe('CRITICAL')
    expect(batch.findingsCount).toBe(2)
  })
})
