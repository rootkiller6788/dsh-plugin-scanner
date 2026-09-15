/**
 * Capability + supply-chain analyzer. Pattern rules (dynamic execution,
 * dangerous imports) read their `matches` from the rule pack; the AND-shaped
 * rules (credential exfiltration, tool shadowing) and lifecycle scripts stay
 * structural here.
 * @module dsh-plugin-scan-rules/analyzers/capability-analyzer
 */

import type { Analyzer, Finding, ScanInput } from 'dsh-plugin-scan'
import { DEFAULT_BUILTIN_TOOLS, finding, hasMatch } from '../rules.ts'

const NETWORK_RE = /\bfetch\s*\(|node:(?:http|https)|\bXMLHttpRequest\b|\bWebSocket\b/u
const PROCESS_ENV_RE = /\bprocess\.env\b/u
const TOOL_REGISTER_RE = /\b(?:ctx\.tools\.register|defineTool)\b/u

const LIFECYCLE_SCRIPTS = ['preinstall', 'postinstall', 'prepare'] as const

export interface CapabilityAnalyzerConfig {
  /** Tool names treated as built-ins a plugin must not shadow. */
  builtinToolNames?: readonly string[]
}

/** Build the capability + supply-chain detector. */
export function makeCapabilityAnalyzer(config: CapabilityAnalyzerConfig = {}): Analyzer {
  const builtinTools = config.builtinToolNames ?? DEFAULT_BUILTIN_TOOLS
  const name = 'capability-analyzer'
  return {
    name,
    analyze(input: ScanInput): Finding[] {
      const out: Finding[] = []
      const { pkg } = input

      for (const file of pkg.files) {
        if (file.kind !== 'source') continue
        if (hasMatch(file.content, 'CAP_DYNAMIC_EXEC')) {
          out.push(finding({
            analyzer: name,
            ruleId: 'CAP_DYNAMIC_EXEC',
            title: 'Dynamic code execution',
            description: 'The source evaluates code at runtime, defeating static review.',
            filePath: file.path,
            remediation: 'Avoid eval / new Function / node:vm in plugin source.',
          }))
        }
        if (hasMatch(file.content, 'CAP_DANGEROUS_IMPORT')) {
          out.push(finding({
            analyzer: name,
            ruleId: 'CAP_DANGEROUS_IMPORT',
            title: 'Dangerous Node builtin import',
            description: 'The source imports a dangerous Node builtin, which is unusual for a pure plugin.',
            filePath: file.path,
            remediation: 'Route filesystem/process access through ctx.fs / ctx.subprocess instead of raw builtins.',
          }))
        }
        if (PROCESS_ENV_RE.test(file.content) && NETWORK_RE.test(file.content)) {
          out.push(finding({
            analyzer: name,
            ruleId: 'CAP_CREDENTIAL_EXFIL',
            title: 'Credential exfiltration shape',
            description: 'The source reads process.env and performs network I/O.',
            filePath: file.path,
            remediation: 'Resolve secrets through ctx.credentials and never send raw env values off-process.',
          }))
        }
        if (TOOL_REGISTER_RE.test(file.content)) {
          for (const builtin of builtinTools) {
            if (file.content.includes(`name: '${builtin}'`) || file.content.includes(`name: "${builtin}"`)) {
              out.push(finding({
                analyzer: name,
                ruleId: 'CAP_TOOL_SHADOW',
                title: `Shadows built-in tool "${builtin}"`,
                description: `The source registers a tool named "${builtin}", shadowing the built-in tool.`,
                filePath: file.path,
                remediation: `Rename the tool; "${builtin}" is already provided by the harness.`,
              }))
            }
          }
        }
      }

      const scripts = pkg.scripts ?? {}
      for (const script of LIFECYCLE_SCRIPTS) {
        if (typeof scripts[script] === 'string') {
          out.push(finding({
            analyzer: name,
            ruleId: 'SUPPLY_LIFECYCLE_SCRIPT',
            title: `Lifecycle script "${script}"`,
            description: `package.json declares a "${script}" script that runs during install.`,
            filePath: 'package.json',
            remediation: 'Remove the lifecycle script or audit it before allowing the build.',
          }))
        }
      }

      return out
    },
  }
}
