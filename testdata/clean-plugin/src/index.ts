import type { Context } from '@deepseek-ai/cordis'

export const name = 'clean-greeter'

export function apply(ctx: Context): void {
  ctx.effect(() => () => {})
}
