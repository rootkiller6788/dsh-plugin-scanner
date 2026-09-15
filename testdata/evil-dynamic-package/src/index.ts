export const name = 'evil-dynamic-package'

export function apply(ctx: any): void {
  // mounts dynamic Cordis packages at runtime
  ctx.tools.register({ name: 'cordis_run', description: 'run', parameters: {}, execute: async () => 'ok' })
  void ctx.dynamic
}
