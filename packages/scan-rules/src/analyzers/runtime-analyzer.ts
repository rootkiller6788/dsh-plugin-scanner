/**
 * Runtime-face analyzer: dynamic Cordis packages (pattern) and self-modification
 * shapes (structural AND). Static scanning can only flag these as suspicious,
 * never prove harm.
 * @module dsh-plugin-scan-rules/analyzers/runtime-analyzer
 */

import type { Analyzer, Finding, ScanInput } from 'dsh-plugin-scan'
import { finding, matcherFor } from '../rules.ts'

const WRITE_RE = /\b(?:writeFile|appendFile|writeFileSync|appendFileSync|outputFile|outputFileSync)\s*\(/u
const TARGET_RE = /(?:cordis\.(?:yml|yaml)|cordis\.patch|profiles?\/|\.dsh\b)/u

/** Build the runtime-face detector. */
export function makeRuntimeAnalyzer(): Analyzer {
  const name = 'runtime-analyzer'
  return {
    name,
    analyze(input: ScanInput): Finding[] {
      const out: Finding[] = []
      for (const file of input.pkg.files) {
        if (file.kind !== 'source') continue
        if (matcherFor(file.content).has('RUNTIME_DYNAMIC_PACKAGE')) {
          out.push(finding({
            analyzer: name,
            ruleId: 'RUNTIME_DYNAMIC_PACKAGE',
            title: 'Drives dynamic Cordis packages',
            description: 'The source references cordis_define / cordis_run / ctx.dynamic; dynamic packages affect the live runtime.',
            filePath: file.path,
            remediation: 'Prefer a normal installed plugin over a dynamic package for anything persistent.',
          }))
        }
        if (WRITE_RE.test(file.content) && TARGET_RE.test(file.content)) {
          out.push(finding({
            analyzer: name,
            ruleId: 'RUNTIME_SELF_MODIFY',
            title: 'Self-modification shape',
            description: 'The source writes to cordis.yml / profile / harness-home state.',
            filePath: file.path,
            remediation: 'Do not let plugin code rewrite the harness configuration.',
          }))
        }
      }
      return out
    },
  }
}
