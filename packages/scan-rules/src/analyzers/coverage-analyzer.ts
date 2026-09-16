/**
 * Coverage analyzer: reports on the scan's own completeness. Every other
 * detector answers "what did I see?"; this one answers "what did the loader
 * never hand me?" — a package whose payload sits in a file the loader refused
 * is otherwise indistinguishable from a clean one.
 * @module dsh-plugin-scan-rules/analyzers/coverage-analyzer
 */

import type { Analyzer, Finding, JsonValue, ScanInput, SkipReason } from 'dsh-plugin-scan'
import { finding } from '../rules.ts'

/** How many offending paths a finding spells out before summarizing. */
const MAX_LISTED_PATHS = 5

/** Human-readable explanation per skip reason. */
const REASON_TEXT: Record<SkipReason, string> = {
  oversized: `over the per-file size cap, so it was not read`,
  unreadable: 'unreadable',
  budget: `over the scan's total byte budget, so it was not read`,
}

/** `a.ts, b.ts, c.ts and 4 more`, bounded so one finding stays readable. */
function summarize(paths: readonly string[]): string {
  const listed = paths.slice(0, MAX_LISTED_PATHS).join(', ')
  const rest = paths.length - MAX_LISTED_PATHS
  return rest > 0 ? `${listed} and ${rest} more` : listed
}

/** Build the scan-coverage detector. */
export function makeCoverageAnalyzer(): Analyzer {
  const name = 'coverage-analyzer'
  return {
    name,
    analyze(input: ScanInput): Finding[] {
      const out: Finding[] = []
      const { skipped, truncated } = input.pkg

      if (truncated) {
        out.push(finding({
          analyzer: name,
          ruleId: 'SCAN_TRUNCATED',
          title: 'Scan stopped before covering the whole package',
          description: 'The package holds more files than the loader collects in one pass, so the detectors saw only part of it.',
          filePath: 'package.json',
          remediation: 'Treat these findings as partial; scan the package in parts or raise the loader limits for a trusted package.',
        }))
      }

      const byReason = new Map<SkipReason, string[]>()
      for (const file of skipped) {
        const paths = byReason.get(file.reason)
        if (paths === undefined) byReason.set(file.reason, [file.path])
        else paths.push(file.path)
      }
      for (const [reason, paths] of byReason) {
        out.push(finding({
          analyzer: name,
          ruleId: 'SCAN_FILE_SKIPPED',
          title: `${paths.length} file(s) not scanned`,
          description: `${paths.length} file(s) were ${REASON_TEXT[reason]}: ${summarize(paths)}. No detector can match content the loader never read.`,
          filePath: paths[0],
          remediation: 'Review these files by hand, or scan a trimmed copy of the package.',
          metadata: { reason, count: paths.length, paths: paths.slice(0, MAX_LISTED_PATHS) as JsonValue[] },
        }))
      }

      return out
    },
  }
}
