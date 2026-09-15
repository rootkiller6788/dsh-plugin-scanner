import { describe, expect, it } from 'vitest'
import { CORE_PACK, finding, hasMatch, matchesFor, matcherFor, rule } from '../src/rules.ts'

/**
 * Count `String.prototype.toLowerCase` calls while `body` runs. The analyzers
 * fold each file once and query several rules against it; this pins that the
 * fold stays O(1) per file rather than O(1) per rule.
 */
function countFolds<T>(body: () => T): { result: T; folds: number } {
  const original = String.prototype.toLowerCase
  let folds = 0
  String.prototype.toLowerCase = function (this: string): string {
    folds += 1
    return original.call(this)
  }
  try {
    return { result: body(), folds }
  } finally {
    String.prototype.toLowerCase = original
  }
}

describe('core rule pack (YAML)', () => {
  it('loads the manifest from rules/core.yaml', () => {
    expect(CORE_PACK.name).toBe('core')
    expect(rule('CAP_DANGEROUS_IMPORT').severity).toBe('MEDIUM')
    expect(rule('CONFIG_TRUSTED_ROW_DISABLED').severity).toBe('CRITICAL')
  })

  it('exposes the case-insensitive match lists', () => {
    expect(matchesFor('CAP_DANGEROUS_IMPORT')).toContain('node:fs')
    expect(hasMatch("from 'node:fs'", 'CAP_DANGEROUS_IMPORT')).toBe(true)
    expect(hasMatch('ignore previous INSTRUCTIONS', 'PROMPT_INJECTION_IGNORE')).toBe(true)
  })

  it('folds a file once and then answers every rule from that fold', () => {
    const content = "import { readFileSync } from 'node:fs'\n// IGNORE PREVIOUS INSTRUCTIONS\neval(x)\n"
    const { result, folds } = countFolds(() => {
      const matches = matcherFor(content)
      return [
        matches.has('CAP_DANGEROUS_IMPORT'),
        matches.has('CAP_DYNAMIC_EXEC'),
        matches.has('PROMPT_INJECTION_IGNORE'),
        matches.has('CONFIG_JS_EXPRESSION'),
        matches.has('CAP_DANGEROUS_IMPORT'),
      ]
    })

    expect(result).toEqual([true, true, true, false, true])
    expect(folds).toBe(1)
  })

  it('answers an unknown or match-less rule without folding', () => {
    // CONFIG_JS_CAPABILITY has needles, RUNTIME_SELF_MODIFY has none.
    expect(matcherFor('anything').has('RUNTIME_SELF_MODIFY')).toBe(false)
    const { result, folds } = countFolds(() => matcherFor('x'.repeat(64)).has('NOT_A_RULE'))
    expect(result).toBe(false)
    expect(folds).toBe(0)
  })

  it('fails loud when emitting a rule missing from the manifest', () => {
    expect(() => finding({ analyzer: 'x', ruleId: 'NOT_IN_PACK', title: 't', description: 'd' })).toThrow(/manifest/)
  })
})
