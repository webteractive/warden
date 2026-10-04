import type { FsStat, On } from 'claude-code'
import { mock } from 'claude-code/testing'

import type { EnvRow, Problem } from '../types'

// Stands for the engine and for warden beneath the mod. The fake warden decides
// the guard the way the real one does for the inputs these tests use, and
// answers doctor/list/set from the fixture. It never holds a value.

export type FakeWarden = {
  // false: `warden` cannot be started at all.
  installed: boolean
  // false: a binary older than `hook --guard --json`.
  json: boolean
  darwin: boolean
  doctor: { project: Problem[] | 'no-env-file'; global: Problem[] | 'no-env-file' }
  list: { project: Omit<EnvRow, 'flags'>[]; global: Omit<EnvRow, 'flags'>[] }
  setExit: number
}

export type Seen = {
  runs: { argv: string[]; stdin?: string; timeoutMs?: number; cwd?: string }[]
  toasts: string[]
  logs: string[]
  statuses: (string | undefined)[]
  fills: string[]
  opened: string[]
  stored: unknown[]
}

export const HOME = '/Users/me'
export const CWD = '/work/app'

export function fakeWarden(overrides: Partial<FakeWarden> = {}): FakeWarden {
  return {
    installed: true,
    json: true,
    darwin: true,
    doctor: { project: [], global: [] },
    list: { project: [], global: [] },
    setExit: 0,
    ...overrides,
  }
}

const WARDEN = new Set(['warden', `${HOME}/.local/bin/warden`])

// warden's guard, reduced to what these tests ask it: a call naming a
// protected file and a reader is denied; the readable names are not.
function guard(stdin: string): { exitCode: number; stdout: string } {
  const readable = /\.env\.(example|schema|sample|dist)\b/
  const text = stdin.replace(new RegExp(readable.source, 'g'), '')
  const named = /\.secrets/.test(text) ? 'secrets' : /\.env/.test(text) ? 'env' : undefined
  if (named === undefined || /"command":"warden /.test(stdin)) {
    return { exitCode: 0, stdout: '{"decision":"allow"}\n' }
  }
  const reason = `Denied: reading ${named === 'secrets' ? '.secrets' : '.env'} directly.\n\nUse warden: warden has KEY`
  return { exitCode: 2, stdout: `${JSON.stringify({ decision: 'deny', target: named, reason })}\n` }
}

function answer(w: FakeWarden, argv: readonly string[], stdin?: string): { exitCode: number; stdout: string; stderr: string } {
  const ok = (stdout: string) => ({ exitCode: 0, stdout, stderr: '' })
  const [, verb, ...rest] = argv
  const scope = rest.includes('--global') ? 'global' : 'project'
  const noFile = { exitCode: 3, stdout: '', stderr: '{"error":{"code":"no-env-file","message":"warden: no env file found"}}\n' }
  switch (verb) {
    case '--version':
      return ok('warden 0.1.6 (abc1234, 2026-10-04)\n')
    case 'hook':
      if (!w.json) return { exitCode: 0, stdout: '', stderr: '' }
      return { ...guard(stdin ?? '{}'), stderr: '' }
    case 'doctor': {
      const found = w.doctor[scope]
      return found === 'no-env-file' ? noFile : ok(`${JSON.stringify(found)}\n`)
    }
    case 'list':
      if (w.doctor[scope] === 'no-env-file') return noFile
      return ok(`${JSON.stringify(w.list[scope])}\n`)
    case 'classify':
      return ok(`${JSON.stringify({ key: rest.at(-1), class: 'secret', rule: 'name:*SECRET*' })}\n`)
    case 'set':
      return w.setExit === 0
        ? ok(`ok: ${rest.at(-1)} set (secret) in .env\n`)
        : { exitCode: w.setExit, stdout: '', stderr: 'warden: cancelled\n' }
    default:
      return { exitCode: 3, stdout: '', stderr: 'unknown command\n' }
  }
}

export type WorldOptions = {
  warden?: FakeWarden
  files?: string[]
  panes?: string[]
}

export function world(on: On, options: WorldOptions = {}): Seen {
  const w = options.warden ?? fakeWarden()
  const seen: Seen = { runs: [], toasts: [], logs: [], statuses: [], fills: [], opened: [], stored: [] }
  let now = Date.parse('2026-10-04T05:00:00.000Z')

  mock.env(on, { HOME })
  on('clock.now', () => {
    now += 1_000
    return { value: now }
  })
  on('session.cwd', () => ({ value: CWD }))
  on('session.start', (_$, e) => ({ cwd: e.cwd }))
  on('turn.complete', () => ({ text: '' }))
  on('command.register', (_$, e) => ({ value: { command: e.name } }))
  on('ui.toast', (_$, e) => {
    seen.toasts.push(e.text)
    return { value: undefined }
  })
  on('ui.log', (_$, e) => {
    seen.logs.push(e.text)
    return { value: undefined }
  })
  on('ui.status', (_$, e) => {
    seen.statuses.push(e.text)
    return { value: undefined }
  })
  on('ui.open', (_$, e) => {
    seen.opened.push(e.id)
    return { value: { isPlaced: true } }
  })
  on('ui.close', () => ({ value: undefined }))
  on('ui.panes', () => ({
    value: (options.panes ?? []).map(id => ({ id, title: id, isShown: true, isFocused: false, isPlaced: true })),
  }))
  on('prompt.fill', (_$, e) => {
    seen.fills.push(e.text)
    return { isFilled: true }
  })
  on('fs.stat', (_$, e) => {
    const isFile = options.files?.includes(e.path) ?? true
    if (!isFile) throw new Error('ENOENT')
    const stat: FsStat = {
      kind: 'file', size: 1, mtimeMs: 0, isLink: false,
      ...(e.resolve ? { realPath: e.path } : {}),
    }
    return { value: stat }
  })
  on('process.run', (_$, e) => {
    seen.runs.push({ argv: [...e.argv], stdin: e.init?.stdin, timeoutMs: e.init?.timeoutMs, cwd: e.init?.cwd })
    const bin = e.argv[0] ?? ''
    if (bin === 'uname') {
      return { value: { exitCode: 0, stdout: w.darwin ? 'Darwin\n' : 'Linux\n', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
    }
    if (!w.installed || !WARDEN.has(bin)) throw new Error(`spawn ${bin} ENOENT`)
    const ran = answer(w, e.argv, e.init?.stdin)
    return { value: { ...ran, isStdoutTruncated: false, isStderrTruncated: false } }
  })
  // The kit has no store beneath session.append, and a row is never answered
  // without next, so this records what the mod hands down — the row as it
  // would be stored — and passes it on to the bottom, which rejects.
  on('session.append', (_$, e, next) => {
    seen.stored.push(e.message)
    return next(e)
  })
  return seen
}

// The guard's warden calls, as opposed to probes and health checks.
export function guardRuns(seen: Seen): Seen['runs'] {
  return seen.runs.filter(r => r.argv[1] === 'hook' && r.stdin !== '{}')
}

export const PROBLEMS: Problem[] = [
  { code: 'perms', severity: 'error', message: '/work/app/.env has permissions 0644 — group or world readable', fix: 'chmod 600 /work/app/.env' },
  { code: 'drift', key: 'STRIPE_SECRET', severity: 'warn', message: 'STRIPE_SECRET is declared in .env.example but not set', fix: 'warden set --secret STRIPE_SECRET' },
  { code: 'multiline', key: 'TLS_KEY', severity: 'info', message: 'TLS_KEY holds a multi-line value (16 lines), stored escaped on one line' },
]
