/**
 * Directory loader: turn a `ScanTarget` into a bounded {@link PluginPackage}.
 *
 * Mirrors the bounded-scan posture of skill-scanner: a hard cap on visited
 * directories and per-file bytes so a hostile tree (symlink fan-out, huge file)
 * cannot turn a scan into a full-filesystem crawl. The v1 loader is synchronous
 * and small; loading is a bounded, fast step before the async analyzer pass.
 * @module dsh-plugin-scan/load
 */

import { readdirSync, readFileSync, rmSync, mkdtempSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { homedir, tmpdir } from 'node:os'
import { join, relative, resolve } from 'node:path'
import yaml, { Type } from 'js-yaml'
import type { CordisRow, PluginFile, PluginFileKind, PluginPackage, ScanTarget } from './index.ts'

/** Upper bound on directories visited during a recursive walk. */
const MAX_WALK_DIRS = 10_000
/** Per-file read cap; larger files are skipped rather than slurped. */
const MAX_FILE_BYTES = 256 * 1024
/** Directory names never descended into: deps, VCS, build output, and tests. */
const SKIP_DIRS = new Set(['node_modules', '.git', '.dsh', '.pnpm', 'lib', 'dist', 'tests'])

/** js-yaml type so `!!js` scalars parse as raw strings instead of throwing. */
const JS_EXPR_TYPE = new Type('tag:yaml.org,2002:js', {
  kind: 'scalar',
  resolve: () => true,
  construct: (data) => data as string,
})
const PATCH_SCHEMA = yaml.DEFAULT_SCHEMA.extend([JS_EXPR_TYPE])

/** Classify a file path by extension. */
function fileKind(path: string): PluginFileKind {
  if (path === 'package.json') return 'manifest'
  if (/\.(?:yml|yaml)$/u.test(path)) return 'config'
  if (/\.(?:ts|js|mjs|cjs|tsx|jsx)$/u.test(path)) return 'source'
  if (/\.md$/u.test(path)) return 'markdown'
  if (/\.json$/u.test(path)) return 'json'
  return 'other'
}

/** Read a file bounded by {@link MAX_FILE_BYTES}; oversized or unreadable files become empty. */
function readText(path: string): string {
  try {
    const content = readFileSync(path)
    if (content.byteLength > MAX_FILE_BYTES) return ''
    return content.toString('utf8')
  } catch {
    return ''
  }
}

/**
 * A walked file whose content is read on first access and then memoized.
 *
 * The walk needs only the path and the kind (derived from the path), and a real
 * plugin package carries plenty of bytes no analyzer will ever inspect — a
 * marketplace's `data/registry.json` is 800 KB of JSON that no detector reads.
 * Reading on demand keeps those bytes off the scan's critical path and out of
 * the retained package model.
 */
function lazyFile(root: string, rel: string, kind: PluginFileKind): PluginFile {
  let content: string | undefined
  return {
    path: rel,
    kind,
    get content(): string {
      content ??= readText(join(root, rel))
      return content
    },
  }
}

/** Walk a package directory collecting file entries with lazy content. */
function walkFiles(root: string): PluginFile[] {
  const files: PluginFile[] = []
  let dirs = 0
  const stack: string[] = [root]
  while (stack.length > 0) {
    const dir = stack.pop()
    if (dir === undefined) break
    if (++dirs > MAX_WALK_DIRS) break
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      const abs = join(dir, entry.name)
      const rel = relative(root, abs).split('\\').join('/')
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(abs)
      } else if (entry.isFile()) {
        if (entry.name === 'package.json' || entry.name === 'cordis.patch.yml') continue
        files.push(lazyFile(root, rel, fileKind(rel)))
      }
    }
  }
  return files
}

/** Parse a `cordis.patch.yml` into resolvable rows, tolerating `!!js`. */
function parsePatchRows(content: string): { rows: CordisRow[]; raw: string } {
  let doc: unknown
  try {
    doc = yaml.load(content, { schema: PATCH_SCHEMA })
  } catch {
    doc = undefined
  }
  if (!Array.isArray(doc)) return { rows: [], raw: content }
  const rows: CordisRow[] = []
  for (const item of doc) {
    if (item === null || typeof item !== 'object') continue
    const record = item as Record<string, unknown>
    if (Array.isArray(record.insert)) {
      for (const inserted of record.insert) {
        if (inserted === null || typeof inserted !== 'object') continue
        const row = inserted as Record<string, unknown>
        if (typeof row.id === 'string') {
          rows.push({
            id: row.id,
            name: typeof row.name === 'string' ? row.name : undefined,
            config: row.config,
            disabled: row.disabled === true,
          })
        }
      }
    } else if (typeof record.id === 'string') {
      rows.push({
        id: record.id,
        name: typeof record.name === 'string' ? record.name : undefined,
        config: record.config,
        disabled: record.disabled === true,
      })
    }
  }
  return { rows, raw: content }
}

/** Resolve a profile target to its on-disk directory (`$DSH_HOME/profiles/<name>`). */
function resolveProfileDir(name: string): string {
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
  return join(home, 'profiles', name)
}

/** Expand an `owner/name` shorthand to a GitHub URL; other forms pass through. */
function repoUrl(repo: string): string {
  return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repo) ? `https://github.com/${repo}.git` : repo
}

/** Shallow-clone a repo into a fresh temp dir. @returns the temp dir path. */
function cloneRepo(repo: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-scan-repo-'))
  try {
    execFileSync('git', ['clone', '--depth', '1', '--quiet', repoUrl(repo), dir], { stdio: 'ignore', timeout: 60_000 })
  } catch (error) {
    rmSync(dir, { recursive: true, force: true })
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`git clone failed for ${repo}: ${message}`)
  }
  return dir
}

/** Map a scan target to a filesystem root, plus whether the root is a temp clone. */
function resolveScanRoot(target: ScanTarget): { root: string; tempRoot?: string } {
  switch (target.kind) {
    case 'directory':
      return { root: resolve(target.path) }
    case 'profile':
      return { root: resolveProfileDir(target.name) }
    case 'github': {
      const root = cloneRepo(target.repo)
      return { root, tempRoot: root }
    }
    case 'registry':
      throw new Error('scan target kind "registry" is batch; use scanRegistry(path) instead')
  }
}

/**
 * Load a plugin package from a target.
 * @param target - a directory, profile, or github repo; `registry` is not implemented in v1.
 * @returns the bounded package model.
 */
export function loadPluginPackage(target: ScanTarget): PluginPackage {
  const { root, tempRoot } = resolveScanRoot(target)

  let name = 'unknown'
  let version: string | undefined
  let manifest: string | undefined
  let scripts: Record<string, string> | undefined
  let dependencies: Record<string, string> | undefined
  try {
    manifest = readText(join(root, 'package.json'))
    const parsed = JSON.parse(manifest) as Record<string, unknown>
    name = typeof parsed.name === 'string' ? parsed.name : name
    version = typeof parsed.version === 'string' ? parsed.version : undefined
    if (parsed.scripts !== null && typeof parsed.scripts === 'object') {
      scripts = parsed.scripts as Record<string, string>
    }
    if (parsed.dependencies !== null && typeof parsed.dependencies === 'object') {
      dependencies = parsed.dependencies as Record<string, string>
    }
  } catch {
    manifest = undefined
  }

  let patchRaw: string | undefined
  let patchRows: CordisRow[] = []
  try {
    const patchText = readText(join(root, 'cordis.patch.yml'))
    const parsed = parsePatchRows(patchText)
    patchRaw = parsed.raw
    patchRows = parsed.rows
  } catch {
    patchRaw = undefined
    patchRows = []
  }

  return { root, name, version, manifest, scripts, dependencies, patchRows, patchRaw, files: walkFiles(root), tempRoot }
}

/** Remove a package's ephemeral clone root, if any. */
export function cleanupPackage(pkg: PluginPackage): void {
  if (pkg.tempRoot !== undefined) {
    rmSync(pkg.tempRoot, { recursive: true, force: true })
  }
}

/**
 * Read a registry JSON file into scan targets. The file is an array of
 * `{ name, path }` (local directory) or `{ name, repo }` (github) entries.
 * @param path - path to the registry JSON file.
 * @returns the ordered scan targets.
 */
export function readRegistryTargets(path: string): ScanTarget[] {
  const text = readFileSync(resolve(path), 'utf8')
  let doc: unknown
  try {
    doc = JSON.parse(text)
  } catch {
    throw new Error(`registry file "${path}" is not valid JSON`)
  }
  if (!Array.isArray(doc)) throw new Error(`registry file "${path}" must be a top-level array`)
  return doc.map((entry, index) => {
    if (entry === null || typeof entry !== 'object') {
      throw new Error(`registry entry ${index} is not an object`)
    }
    const { name, path: dir, repo } = entry as Record<string, unknown>
    if (typeof dir === 'string') return { kind: 'directory', path: dir } satisfies ScanTarget
    if (typeof repo === 'string') return { kind: 'github', repo } satisfies ScanTarget
    throw new Error(`registry entry ${index} (${String(name)}) has neither a path nor a repo`)
  })
}
