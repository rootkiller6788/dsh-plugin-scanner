// Minimal external scan engine fixture for the bridge tests.
// Speaks the bridge protocol over stdin/stdout JSON lines: flags any package
// whose package.json `name` contains "evil".
import { readFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { join } from 'node:path'

const ENGINE_VERSION = '1.0.0'

/** `--pad=N --pad-char=C` pads every finding description, to test the line cap. */
const flag = (name) => process.argv.find((arg) => arg.startsWith(`--${name}=`))?.slice(name.length + 3) ?? ''
const PAD = Number(flag('pad') || 0)
const PAD_CHAR = flag('pad-char') || 'x'

const send = (message) => {
  process.stdout.write(JSON.stringify(message) + '\n')
}

const rl = createInterface({ input: process.stdin })
rl.on('line', (line) => {
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
        ENGINE_EVIL: { severity: 'HIGH', category: 'supply_chain', description: 'package name contains "evil"' },
      },
    })
    return
  }
  if (message.op === 'scan') {
    let name = 'unknown'
    try {
      name = JSON.parse(readFileSync(join(message.root, 'package.json'), 'utf8')).name ?? 'unknown'
    } catch {
      // leave name unknown
    }
    if (name.includes('evil')) {
      send({
        op: 'findings',
        id: message.id,
        findings: [{
          ruleId: 'ENGINE_EVIL',
          title: 'Engine-detected evil package',
          description: `package name "${name}" contains "evil"${PAD_CHAR.repeat(PAD)}`,
          filePath: 'package.json',
        }],
      })
    } else {
      send({ op: 'findings', id: message.id, findings: [] })
    }
  }
})
