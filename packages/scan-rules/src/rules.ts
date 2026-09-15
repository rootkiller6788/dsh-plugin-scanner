/**
 * Core rule-pack loader: reads and validates `rules/core.yaml` into the
 * manifest every built-in analyzer emits against, plus the per-rule
 * case-insensitive substring `matches` lists. `finding()` looks a rule up at
 * emit time and fails loud on a missing entry, the same "no rule drifts out of
 * the pack" contract skill-scanner enforces for its YAML packs.
 * @module dsh-plugin-scan-rules/rules
 */

import { readFileSync } from 'node:fs'
import { load } from 'js-yaml'
import {
  SEVERITIES,
  THREAT_CATEGORIES,
  type Finding,
  type RuleMeta,
  type RulePack,
  type Severity,
  type ThreatCategory,
} from 'dsh-plugin-scan'

/** Security-relevant row ids a plugin patch should not override or disable. */
export const DEFAULT_TRUSTED_ROWS = [
  'sandbox',
  'sandbox-policy',
  'approval',
  'permission',
  'credentials',
  'llm',
  'llm-retry',
  'llm-pi-ai',
  'llm-deepseek',
  'fs-sandbox',
] as const

/** Built-in tool names a plugin must not shadow. */
export const DEFAULT_BUILTIN_TOOLS = [
  'skill',
  'bash',
  'read',
  'write',
  'edit',
  'grep',
  'glob',
  'todo_write',
  'web_search',
  'web_fetch',
] as const

interface RawRule {
  severity?: unknown
  category?: unknown
  description?: unknown
  matches?: unknown
}

interface RawPack {
  name?: unknown
  rules?: unknown
}

function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value)
}

function isCategory(value: unknown): value is ThreatCategory {
  return typeof value === 'string' && (THREAT_CATEGORIES as readonly string[]).includes(value)
}

/** Load and validate the bundled core pack, failing loud on any malformed rule. */
function loadCorePack(): { manifest: RulePack; matches: Record<string, string[]> } {
  const text = readFileSync(new URL('../rules/core.yaml', import.meta.url), 'utf8')
  const doc = load(text) as RawPack
  if (typeof doc.name !== 'string') throw new Error('core rule pack is missing a name')
  if (doc.rules === null || typeof doc.rules !== 'object' || Array.isArray(doc.rules)) {
    throw new Error('core rule pack is missing a rules map')
  }
  const manifest: Record<string, RuleMeta> = {}
  const matches: Record<string, string[]> = {}
  for (const [ruleId, raw] of Object.entries(doc.rules as Record<string, RawRule>)) {
    if (!isSeverity(raw.severity)) throw new Error(`rule ${ruleId} has an invalid severity`)
    if (!isCategory(raw.category)) throw new Error(`rule ${ruleId} has an invalid category`)
    if (typeof raw.description !== 'string' || raw.description.length === 0) {
      throw new Error(`rule ${ruleId} has no description`)
    }
    manifest[ruleId] = { severity: raw.severity, category: raw.category, description: raw.description }
    if (raw.matches !== undefined) {
      if (!Array.isArray(raw.matches) || raw.matches.some((m) => typeof m !== 'string' || m.length === 0)) {
        throw new Error(`rule ${ruleId} has an invalid matches list`)
      }
      matches[ruleId] = raw.matches as string[]
    }
  }
  return { manifest: { name: doc.name, rules: manifest }, matches }
}

const { manifest: CORE_PACK, matches: CORE_MATCHES } = loadCorePack()

/**
 * The `matches` lists with the case folding already applied. Matching is
 * case-insensitive, so the fold is a constant of the pack — doing it here
 * removes a `toLowerCase` per needle from every file the analyzers visit.
 */
const CORE_NEEDLES: Readonly<Record<string, readonly string[]>> = Object.fromEntries(
  Object.entries(CORE_MATCHES).map(([ruleId, needles]) => [ruleId, needles.map((needle) => needle.toLowerCase())]),
)

export { CORE_PACK }

/** Look up a rule, failing loud when it has no manifest entry. */
export function rule(ruleId: string): RuleMeta {
  const meta = CORE_PACK.rules[ruleId]
  if (meta === undefined) {
    throw new Error(`rule "${ruleId}" has no manifest entry in the core pack`)
  }
  return meta
}

/** The case-insensitive substring list for a pattern rule, as authored. */
export function matchesFor(ruleId: string): readonly string[] {
  return CORE_MATCHES[ruleId] ?? []
}

/**
 * A single file's content, folded for matching once and then queried by any
 * number of rules. Analyzers build one per file: lowercasing the whole file is
 * the scanner's largest per-file allocation, so it must not be paid per rule.
 */
export interface RuleMatcher {
  /** Whether the content contains any of `ruleId`'s `matches` (case-insensitive). */
  has(ruleId: string): boolean
}

/** Build a {@link RuleMatcher} over `content`. */
export function matcherFor(content: string): RuleMatcher {
  let folded: string | undefined
  return {
    has(ruleId: string): boolean {
      const needles = CORE_NEEDLES[ruleId]
      if (needles === undefined || needles.length === 0) return false
      folded ??= content.toLowerCase()
      return needles.some((needle) => folded!.includes(needle))
    },
  }
}

/** Whether `content` contains any of a rule's `matches` (case-insensitive). */
export function hasMatch(content: string, ruleId: string): boolean {
  return matcherFor(content).has(ruleId)
}

/** Build a {@link Finding} whose severity/category come from the manifest. */
export function finding(opts: {
  analyzer: string
  ruleId: string
  title: string
  description: string
  filePath?: string
  line?: number
  snippet?: string
  remediation?: string
}): Finding {
  const meta = rule(opts.ruleId)
  return {
    id: `${opts.ruleId}:${opts.filePath ?? ''}:${opts.line ?? 0}`,
    ruleId: opts.ruleId,
    category: meta.category as ThreatCategory,
    severity: meta.severity as Severity,
    title: opts.title,
    description: opts.description,
    filePath: opts.filePath,
    line: opts.line,
    snippet: opts.snippet,
    remediation: opts.remediation,
    analyzer: opts.analyzer,
  }
}
