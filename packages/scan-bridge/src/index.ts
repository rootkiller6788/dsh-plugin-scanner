/**
 * External-engine Provider: registers a subprocess detector on `ctx.pluginScan`.
 * This is the pluginized-core proof — it adds detection capability through the
 * same `registerAnalyzer` effect the built-in analyzers use, without touching
 * `dsh-plugin-scan` or `dsh-plugin-scan-rules`.
 * @module dsh-plugin-scan-bridge
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { makeBridgeAnalyzer } from './bridge.ts'
import type { BridgeConfig } from './bridge.ts'

/** Cordis plugin name. */
export const name = 'plugin-scan-bridge'

/** The scanner registry this plugin registers into. */
export const inject = ['pluginScan']

export interface Config extends BridgeConfig {}

export const Config: z<Config> = z.object({
  command: z.string().required(),
  args: z.array(z.string()).default([]),
  engineName: z.string().required(),
  engineVersion: z.string().required(),
  timeoutMs: z.number().default(5000),
  maxLineBytes: z.number().default(1024 * 1024),
})

/** Register the external engine as an analyzer after an eager, version-pinned handshake. */
export async function apply(ctx: Context, config: Config): Promise<void> {
  const { analyzer, init, close } = makeBridgeAnalyzer(config)
  const rulePack = await init()
  ctx.effect(() => {
    const disposeRule = ctx.pluginScan.registerRulePack(rulePack)
    const disposeAnalyzer = ctx.pluginScan.registerAnalyzer(analyzer)
    return () => {
      disposeAnalyzer()
      disposeRule()
      close()
    }
  })
}
