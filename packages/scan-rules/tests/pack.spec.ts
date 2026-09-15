import { describe, expect, it } from 'vitest'
import { CORE_PACK, finding, hasMatch, matchesFor, rule } from '../src/rules.ts'

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

  it('fails loud when emitting a rule missing from the manifest', () => {
    expect(() => finding({ analyzer: 'x', ruleId: 'NOT_IN_PACK', title: 't', description: 'd' })).toThrow(/manifest/)
  })
})
