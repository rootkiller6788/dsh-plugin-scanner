/**
 * Detection benchmark. Two corpora:
 *  - malicious: `testdata/evil-*` fixtures, each with a known injected threat
 *    and its expected rule id(s) — measures recall (must catch each).
 *  - benign: real first-party dsh plugins from the sibling deepseek-harness
 *    checkout — measures false-positive rate (severity-ranked).
 * Results are also written to `benchmark.txt` for the report.
 * @module dsh-plugin-scan-rules/tests/benchmark
 */

import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it } from 'vitest'
import PluginScanService from 'dsh-plugin-scan'
import * as ScanRules from 'dsh-plugin-scan-rules'

const HARNESS_ROOT = process.env.DSH_HARNESS_ROOT ?? 'D:/Opencode/dsh-plugin/deepseek-harness-master'
const fixture = (name: string) => fileURLToPath(new URL(`../../../testdata/${name}`, import.meta.url))

/** Malicious corpus: fixture name -> expected rule ids. */
const EVIL_CASES: Record<string, string[]> = {
  'evil-config-override': ['CONFIG_TRUSTED_ROW_OVERRIDE', 'CONFIG_TRUSTED_ROW_DISABLED'],
  'evil-js-config': ['CONFIG_JS_EXPRESSION', 'CONFIG_JS_CAPABILITY'],
  'evil-exfil-plugin': ['CAP_DANGEROUS_IMPORT', 'CAP_CREDENTIAL_EXFIL'],
  'evil-tool-shadow': ['CAP_TOOL_SHADOW'],
  'evil-prompt-injection': ['PROMPT_INJECTION_IGNORE'],
  'evil-supply-chain': ['SUPPLY_LIFECYCLE_SCRIPT'],
  'evil-dynamic-package': ['RUNTIME_DYNAMIC_PACKAGE'],
  'evil-self-modify': ['RUNTIME_SELF_MODIFY'],
}

/** Pure first-party plugins expected to be clean of CRITICAL/HIGH. */
const PURE_BENIGN: string[] = [
  'packages/core/session',
  'packages/core/scope',
  'packages/core/system-prompt',
  'packages/skill/skill',
  'packages/goal/goal',
  'packages/plan/plan-mode',
  'packages/guard/repeat-tool-reminder',
  'packages/guard/timeout-policy',
  'packages/compaction/compaction-basic',
  'packages/context/time-context',
  'packages/interaction/commands',
  'packages/typert/protocol',
  'packages/util/brand',
  'packages/util/timeout',
  'packages/runtime-diagnostics/invariants',
]

// First-party providers that legitimately register a built-in tool name, so
// CAP_TOOL_SHADOW flags them. They are NOT "pure": a single-package static scan
// cannot distinguish a tool's owner from a shadowing third party. Scanned only
// to document this known false-positive mode.
const TOOL_PROVIDERS: string[] = [
  'packages/skill/tool-skill',
  'packages/todo/tool-todo',
]

/** Capability-heavy first-party plugins, scanned to show honest usage flags. */
const CAPABILITY_BENIGN: string[] = [
  'packages/market/smart-plugin-market',
  'packages/shell/tool-bash',
]

async function scan(path: string) {
  const ctx = new Context()
  await ctx.plugin(PluginScanService)
  await ctx.plugin(ScanRules)
  return ctx.pluginScan.scan({ kind: 'directory', path })
}

describe('benchmark', () => {
  it('catches every injected threat (recall)', async () => {
    for (const [name, expected] of Object.entries(EVIL_CASES)) {
      const report = await scan(fixture(name))
      const ids = new Set(report.findings.map((f) => f.ruleId))
      for (const ruleId of expected) {
        expect(ids.has(ruleId), `${name} should emit ${ruleId}`).toBe(true)
      }
    }
  })

  it('leaves the clean fixture with zero findings', async () => {
    const report = await scan(fixture('clean-plugin'))
    expect(report.findings).toEqual([])
  })

  it('produces no CRITICAL/HIGH on pure first-party plugins (false-positive gate)', async () => {
    for (const rel of PURE_BENIGN) {
      const report = await scan(`${HARNESS_ROOT}/${rel}`)
      const bad = report.findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
      expect(bad, `${rel} should have no CRITICAL/HIGH findings, got: ${bad.map((f) => f.ruleId).join(', ')}`).toEqual([])
    }
  })

  it('writes the full benchmark report', async () => {
    const lines: string[] = []
    lines.push('# dsh-plugin-scanner benchmark')
    lines.push('')
    lines.push('## Malicious corpus (recall)')
    for (const [name, expected] of Object.entries(EVIL_CASES)) {
      const report = await scan(fixture(name))
      const ids = report.findings.map((f) => f.ruleId)
      const missing = expected.filter((r) => !ids.includes(r))
      lines.push(`- ${name}: ${missing.length === 0 ? 'OK' : `MISSING ${missing.join(',')}`} (found ${ids.join(', ') || 'none'})`)
    }
    lines.push('')
    lines.push('## Benign corpus (false positives)')
    for (const rel of [...PURE_BENIGN, ...TOOL_PROVIDERS, ...CAPABILITY_BENIGN]) {
      const report = await scan(`${HARNESS_ROOT}/${rel}`)
      const bySeverity = report.findings.reduce<Record<string, number>>((acc, f) => {
        acc[f.severity] = (acc[f.severity] ?? 0) + 1
        return acc
      }, {})
      lines.push(`- ${rel}: ${report.findingsCount} finding(s) ${JSON.stringify(bySeverity)}`)
    }
    writeFileSync('D:/Opencode/dsh-plugin/dsh-plugin-scanner/benchmark.txt', lines.join('\n'))
  })
})
