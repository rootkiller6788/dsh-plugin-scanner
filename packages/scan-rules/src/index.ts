/**
 * Built-in analyzer provider: registers the four core detectors and the core
 * rule pack on `ctx.pluginScan`. Each registration is an effect; disposing this
 * plugin withdraws all four analyzers. A third-party detector registers through
 * the exact same `registerAnalyzer` method — there is no privileged factory.
 * @module dsh-plugin-scan-rules
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { makeCapabilityAnalyzer } from './analyzers/capability-analyzer.ts'
import { makeConfigAnalyzer } from './analyzers/config-analyzer.ts'
import { makeModelAnalyzer } from './analyzers/model-analyzer.ts'
import { makeRuntimeAnalyzer } from './analyzers/runtime-analyzer.ts'
import { CORE_PACK, DEFAULT_BUILTIN_TOOLS, DEFAULT_TRUSTED_ROWS } from './rules.ts'

/** Cordis plugin name. */
export const name = 'plugin-scan-rules'

/** The scanner registry this plugin registers into. */
export const inject = ['pluginScan']

export interface Config {
  /** Row ids a patch must not override or disable. */
  trustedRowIds?: string[]
  /** Tool names treated as built-ins a plugin must not shadow. */
  builtinToolNames?: string[]
}

export const Config: z<Config> = z.object({
  trustedRowIds: z.array(z.string()).default([...DEFAULT_TRUSTED_ROWS]),
  builtinToolNames: z.array(z.string()).default([...DEFAULT_BUILTIN_TOOLS]),
})

/** Register the core rule pack and the four built-in analyzers. */
export function apply(ctx: Context, config: Config = {}): void {
  // Each registration is an effect: disposing this plugin withdraws all four
  // analyzers and the pack. A third-party detector registers through the same
  // `registerAnalyzer` + `ctx.effect` pair.
  ctx.effect(() => ctx.pluginScan.registerRulePack(CORE_PACK))
  ctx.effect(() => ctx.pluginScan.registerAnalyzer(makeConfigAnalyzer(config)))
  ctx.effect(() => ctx.pluginScan.registerAnalyzer(makeCapabilityAnalyzer(config)))
  ctx.effect(() => ctx.pluginScan.registerAnalyzer(makeModelAnalyzer()))
  ctx.effect(() => ctx.pluginScan.registerAnalyzer(makeRuntimeAnalyzer()))
}
