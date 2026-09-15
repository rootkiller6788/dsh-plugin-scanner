// Crash fixture for the bridge tests: a healthy engine that can be told to die.
//   --mode=after-scan (default) answer the scan, then exit non-zero
//   --mode=on-scan              write to stderr and exit without answering
// Speaks the same JSON-lines protocol as engine.mjs and flags any package whose
// package.json `name` contains "evil".
import { readFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { join } from 'node:path'

const ENGINE_VERSION = '1.0.0'
const MODE = (process.argv.find((arg) => arg.startsWith('--mode=')) ?? '--mode=after-scan').slice('--mode='.length)

const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`)
const die = (why) => {
  process.stderr.write(`${why}\n`)
  process.exit(1)
}

createInterface({ input: process.stdin }).on('line', (line) => {
  let message
  try {
    message = JSON.parse(line)
  } catch {
    return
  }
  if (message.op === 'init') {
    send({
      op: 'ready',
      version: ENGINE_VERSION,
      rules: {
        CRASH_ENGINE: { severity: 'MEDIUM', category: 'supply_chain', description: 'crash fixture rule' },
      },
    })
    return
  }
  if (message.op !== 'scan') return
  if (MODE === 'on-scan') die('crash-engine: refusing to scan')

  let name = 'unknown'
  try {
    name = JSON.parse(readFileSync(join(message.root, 'package.json'), 'utf8')).name ?? 'unknown'
  } catch {
    // leave name unknown
  }
  send({
    op: 'findings',
    id: message.id,
    findings: name.includes('evil')
      ? [{ ruleId: 'CRASH_ENGINE', title: 'Crash fixture finding', description: `package name "${name}" contains "evil"` }]
      : [],
  })
  // Let the reply reach the parent before the process goes away.
  setTimeout(() => die('crash-engine: exiting after scan'), 20)
})
