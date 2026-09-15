/**
 * Config-face analyzer: patch rows that override or disable security-relevant
 * rows (structural), and `!!js` expressions (pattern, from the rule pack).
 * @module dsh-plugin-scan-rules/analyzers/config-analyzer
 */

import type { Analyzer, Finding, ScanInput } from 'dsh-plugin-scan'
import { DEFAULT_TRUSTED_ROWS, finding, matcherFor } from '../rules.ts'

export interface ConfigAnalyzerConfig {
  /** Row ids a patch must not override or disable. */
  trustedRowIds?: readonly string[]
}

/** Build the config-face detector. */
export function makeConfigAnalyzer(config: ConfigAnalyzerConfig = {}): Analyzer {
  const trusted = new Set(config.trustedRowIds ?? DEFAULT_TRUSTED_ROWS)
  const name = 'config-analyzer'
  return {
    name,
    analyze(input: ScanInput): Finding[] {
      const out: Finding[] = []
      const { patchRows, patchRaw } = input.pkg

      for (const row of patchRows) {
        if (!trusted.has(row.id)) continue
        if (row.disabled === true) {
          out.push(finding({
            analyzer: name,
            ruleId: 'CONFIG_TRUSTED_ROW_DISABLED',
            title: `Trusted row "${row.id}" is disabled`,
            description: `The patch sets disabled: true on the security-relevant "${row.id}" row, removing a guard.`,
            filePath: 'cordis.patch.yml',
            remediation: `Remove the disabled override for "${row.id}" or restrict it to a non-security row.`,
          }))
        } else if (row.config !== undefined) {
          out.push(finding({
            analyzer: name,
            ruleId: 'CONFIG_TRUSTED_ROW_OVERRIDE',
            title: `Trusted row "${row.id}" is overridden`,
            description: `The patch replaces the whole config of the security-relevant "${row.id}" row; a patch replaces, it does not merge.`,
            filePath: 'cordis.patch.yml',
            remediation: `Verify the replacement config for "${row.id}" preserves its security invariants.`,
          }))
        }
      }

      const patchMatches = patchRaw === undefined ? undefined : matcherFor(patchRaw)
      if (patchMatches?.has('CONFIG_JS_EXPRESSION') === true) {
        out.push(finding({
          analyzer: name,
          ruleId: 'CONFIG_JS_EXPRESSION',
          title: 'Patch uses a !!js expression',
          description: 'A !!js expression is evaluated at load time and is arbitrary code, not data.',
          filePath: 'cordis.patch.yml',
          remediation: 'Replace !!js with a literal value or a safe overlay; keep !!js only under plugin config and entry disabled.',
        }))
        if (patchMatches.has('CONFIG_JS_CAPABILITY')) {
          out.push(finding({
            analyzer: name,
            ruleId: 'CONFIG_JS_CAPABILITY',
            title: '!!js expression reaches a capability',
            description: 'The !!js expression references fs/shell/credentials/network or process.env.',
            filePath: 'cordis.patch.yml',
            remediation: 'Do not derive capability configuration from a !!js expression.',
          }))
        }
      }

      return out
    },
  }
}
