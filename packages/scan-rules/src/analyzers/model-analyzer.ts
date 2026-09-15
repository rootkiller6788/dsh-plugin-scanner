/**
 * Model-face analyzer: prompt-injection patterns in anything that becomes
 * model-visible (tool descriptions, prompt sections, SKILL.md / README bodies).
 * Patterns come from the rule pack.
 * @module dsh-plugin-scan-rules/analyzers/model-analyzer
 */

import type { Analyzer, Finding, ScanInput } from 'dsh-plugin-scan'
import { finding, matcherFor } from '../rules.ts'

/** Build the model-face detector. */
export function makeModelAnalyzer(): Analyzer {
  const name = 'model-analyzer'
  return {
    name,
    analyze(input: ScanInput): Finding[] {
      const out: Finding[] = []
      const candidates: { path: string; content: string }[] = []
      for (const file of input.pkg.files) {
        if (file.kind === 'markdown') candidates.push({ path: file.path, content: file.content })
      }
      const manifest = input.pkg.manifest ?? ''
      if (manifest.length > 0) candidates.push({ path: 'package.json', content: manifest })

      for (const { path, content } of candidates) {
        const matches = matcherFor(content)
        if (matches.has('PROMPT_INJECTION_IGNORE')) {
          out.push(finding({
            analyzer: name,
            ruleId: 'PROMPT_INJECTION_IGNORE',
            title: 'Instruction-override directive',
            description: 'Model-visible text instructs the agent to ignore or override prior instructions.',
            filePath: path,
            remediation: 'Remove the override directive; treat any skill/plugin description as untrusted input.',
          }))
        }
        if (matches.has('PROMPT_INJECTION_JAILBREAK')) {
          out.push(finding({
            analyzer: name,
            ruleId: 'PROMPT_INJECTION_JAILBREAK',
            title: 'Jailbreak directive',
            description: 'Model-visible text carries a jailbreak or role-play-escape directive.',
            filePath: path,
            remediation: 'Remove the directive.',
          }))
        }
      }

      return out
    },
  }
}
