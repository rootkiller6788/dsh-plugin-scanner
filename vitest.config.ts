import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['packages/*/tests/**/*.spec.ts'],
    environment: 'node',
  },
  resolve: {
    alias: {
      'dsh-plugin-scan': fileURLToPath(new URL('./packages/scan/src/index.ts', import.meta.url)),
      'dsh-plugin-scan-rules': fileURLToPath(new URL('./packages/scan-rules/src/index.ts', import.meta.url)),
      'dsh-tool-plugin-scan': fileURLToPath(new URL('./packages/tool-scan/src/index.ts', import.meta.url)),
      'dsh-plugin-scan-bridge': fileURLToPath(new URL('./packages/scan-bridge/src/index.ts', import.meta.url)),
    },
  },
})
