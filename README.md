# dsh-plugin-scanner

A security scanner for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`) plugins, built **on the dsh plugin kernel**. It detects risky third-party plugin packages — config row overrides, `!!js` expressions, capability escalation, prompt injection, and self-modification — and reports findings through a model-facing tool and a human-facing command.

## The point: a pluginized core

Reference architecture is [skill-scanner](https://github.com/cisco-ai-defense/skill-scanner), but where skill-scanner has a privileged factory (`analyzer_factory.py` hardcodes the analyzer set), this project makes **analyzer registration an effect**:

- `ctx.pluginScan.registerAnalyzer(analyzer)` returns a disposer, exactly like a Cordis registration.
- The four built-in analyzers (`dsh-plugin-scan-rules`) register through that same public method.
- The external-engine bridge (`dsh-plugin-scan-bridge`) adds a whole detector over a subprocess — also through `registerAnalyzer`, with **no change to the core**.

There is no privileged core to patch. The seam is the standard dsh three-role split:

| Package | Role | `ctx` key |
|---|---|---|
| `dsh-plugin-scan` | Service Definition: analyzer registry, package loader, policy | `ctx.pluginScan` |
| `dsh-plugin-scan-rules` | Service Provider: four built-in analyzers + YAML rule pack | registers on `ctx.pluginScan` |
| `dsh-plugin-scan-bridge` | Service Provider: external engine as a persistent subprocess | registers on `ctx.pluginScan` |
| `dsh-tool-plugin-scan` | Consumer: `scan_plugin` tool + `/scan` command + bundle patch | registers on `ctx.tools`, `ctx.commands` |

## Built-in analyzers

| Analyzer | Detects |
|---|---|
| `config-analyzer` | patch overrides/disables a security-relevant row (`sandbox`, `approval`, `credentials`, `llm`, …); `!!js` expressions and `!!js` reaching `fs`/`shell`/`credentials` |
| `capability-analyzer` | `eval`/`new Function`/`node:vm`; raw `node:fs`/`child_process`/`net` imports; `process.env` + network (credential exfiltration); shadowing a built-in tool name; `preinstall`/`postinstall`/`prepare` scripts |
| `model-analyzer` | prompt-injection directives (ignore-override, jailbreak) in model-visible text |
| `runtime-analyzer` | dynamic Cordis packages (`cordis_define`/`cordis_run`/`ctx.dynamic`); writing `cordis.yml`/profile state |

Rules live in [`packages/scan-rules/rules/core.yaml`](packages/scan-rules/rules/core.yaml): the manifest (severity / category / description) plus per-rule case-insensitive `matches` lists. Structural checks (row overrides, AND-combinations, lifecycle scripts) stay in the analyzer code. Every `ruleId` an analyzer emits must have a manifest entry — `finding()` fails loud on a missing one.

## External engine bridge

`dsh-plugin-scan-bridge` runs any detector as a **persistent subprocess** over a JSON-lines protocol, pinned by version at a handshake and bounded per request (timeout + max line size) — the same versioned, bounded subprocess posture as skill-scanner's cel-go helper. The engine declares its own rules at handshake; they surface in `ctx.pluginScan.ruleRegistry`.

```yaml
# enable a bridge engine in a patch
- insert:
    - id: my-scan-engine
      name: 'dsh-plugin-scan-bridge'
      config:
        command: node
        args: ['./engines/my-engine.mjs']
        engineName: my-engine
        engineVersion: 1.0.0
```

Protocol (JSON lines over stdio): `init {version}` → `ready {version, rules}`; `scan {id, root}` → `findings {id, findings}` | `error {id, error}`. A version mismatch fails plugin load.

## Scan targets

- `{ kind: 'directory', path }` — scan a plugin package directory.
- `{ kind: 'profile', name }` — scan an installed profile's own files (`$DSH_HOME/profiles/<name>`; `DSH_HOME` defaults to `~/.dsh`).
- `{ kind: 'github', repo }` — shallow-clone (`git clone --depth 1`) an `owner/name` (or a full URL / local path) to a temp dir, scan it, then remove the clone.
- `scanRegistry(path)` — batch: read a registry JSON file and scan every entry.

### Registry batch

`scanRegistry(path)` (and the `/scan-registry <path>` command) reads a JSON file of entries and scans each, returning a `ScanBatchReport`:

```json
[
  { "name": "my-plugin", "path": "/abs/path/to/my-plugin" },
  { "name": "someone/some-plugin", "repo": "someone/some-plugin" }
]
```

Each entry carries either a `path` (local directory) or a `repo` (github shorthand / URL).

## Policy and gating

- `ctx.pluginScan` config: `disabledRules` (drop rule ids) and `severityOverrides` (per-rule severity).
- `scan-rules` config: `trustedRowIds`, `builtinToolNames`.
- `tool-scan` config: `failOn` — a severity threshold; the `scan_plugin` result carries `failed: true` when `maxSeverity` reaches it (empty disables).

## Scope and limitations

This is a **best-effort static scanner**, not a security guarantee. "No findings" means no known pattern matched — it does not certify that a plugin is safe. Rules are heuristics (substring + structure, not full AST/dataflow); a determined attacker evades signatures, and the scanner will match a literal token like `eval` even in a comment. Pair results with manual review before installing a plugin you do not trust.

## Repo layout

```
packages/
  scan/         dsh-plugin-scan         (Service Definition)
  scan-rules/   dsh-plugin-scan-rules   (Provider: 4 analyzers + YAML rules)
  scan-bridge/  dsh-plugin-scan-bridge  (Provider: external engine)
  tool-scan/    dsh-tool-plugin-scan    (Consumer: tool + command + bundle)
testdata/       malicious + clean fixtures, and a bridge engine fixture
```

## Development

This repo resolves the dsh framework packages from a sibling `deepseek-harness-master` checkout as workspace members (see `pnpm-workspace.yaml`), so `@deepseek-ai/cordis` keeps a single `Context` identity and the built `lib/` is used for types.

```sh
pnpm install
pnpm run typecheck
pnpm test
```

### Install into a dsh profile

```sh
cd /path/to/deepseek-harness
pnpm dsh plugin --profile web add link:../dsh-plugin-scanner/packages/tool-scan
# or, once published: dsh plugin --profile web add dsh-tool-plugin-scan
```

Then ask the model to `scan_plugin` a directory, or type `/scan <path>`.

## Design notes

- **v1 is report-only.** The tool returns a structured report; it never blocks the model on a finding. Guard/deny behavior and context injection are later milestones.
- **v1 does not add a session event.** Out-of-repo plugins cannot yet mark a new `SessionEventMap` member `ignorable`, so a new event type would make first-party readers refuse resume. Report output rides the existing `tool/result` surface.
- **Exit codes / a CLI are a later milestone**; v1 surfaces the `failed` flag and `maxSeverity` for a caller to gate on.
