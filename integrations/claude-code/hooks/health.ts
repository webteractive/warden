// Reading warden's JSON for the health band and the /env pane, and deciding
// what they show. warden guarantees its JSON carries no value: `message` and
// `fix` name keys and commands, and a secret's fix is the prompted write.
//
// Pure: nothing here touches `$`.

import type { EnvRow, Health, Problem, Scope, Severity, Shown } from '../types'

const SEVERITY_RANK: Readonly<Record<Severity, number>> = { info: 0, warn: 1, error: 2 }

function isSeverity(v: unknown): v is Severity {
  return v === 'info' || v === 'warn' || v === 'error'
}

function parseJSON(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

// `warden doctor --json`: an array of problems, worst first.
export function parseProblems(stdout: string): Problem[] | undefined {
  const parsed = parseJSON(stdout)
  if (!Array.isArray(parsed)) return undefined
  const problems: Problem[] = []
  for (const p of parsed) {
    if (typeof p !== 'object' || p === null) continue
    const r = p as Record<string, unknown>
    if (typeof r.code !== 'string' || typeof r.message !== 'string' || !isSeverity(r.severity)) continue
    problems.push({
      code: r.code,
      severity: r.severity,
      message: r.message,
      ...(typeof r.key === 'string' ? { key: r.key } : {}),
      ...(typeof r.fix === 'string' ? { fix: r.fix } : {}),
    })
  }
  return problems
}

// `warden list --json`: key, class, set — never a value.
export function parseRows(stdout: string): EnvRow[] | undefined {
  const parsed = parseJSON(stdout)
  if (!Array.isArray(parsed)) return undefined
  const rows: EnvRow[] = []
  for (const r of parsed) {
    if (typeof r !== 'object' || r === null) continue
    const o = r as Record<string, unknown>
    if (typeof o.key !== 'string' || typeof o.set !== 'boolean') continue
    rows.push({ key: o.key, class: o.class === 'public' ? 'public' : 'secret', set: o.set, flags: [] })
  }
  return rows
}

// A --json error on stderr: {"error":{"code","message"}}.
export function errorCode(stderr: string): string | undefined {
  const parsed = parseJSON(stderr.trim())
  if (typeof parsed !== 'object' || parsed === null) return undefined
  const error = (parsed as { error?: unknown }).error
  if (typeof error !== 'object' || error === null) return undefined
  const code = (error as { code?: unknown }).code
  return typeof code === 'string' ? code : undefined
}

// A key left empty in a project's .env, or left out of it, is taken as meant:
// .env.example ships blanks, and an app reads a missing or empty value as
// "off". ~/.secrets holds only credentials something reaches for, so an empty
// key there still shows.
function isMeantEmpty(scope: Scope, p: Problem): boolean {
  return scope === 'project' && p.code === 'empty'
}

function isMeantUnset(scope: Scope, p: Problem): boolean {
  return isMeantEmpty(scope, p) || (scope === 'project' && p.code === 'drift')
}

// The problems the band shows, errors before warnings, the project before
// ~/.secrets within a severity. `info` never shows: multi-line values and a
// missing .env.example are worth knowing, not worth a band.
export function shownProblems(health: Health | null, level: Severity): Shown[] {
  if (health === null) return []
  const floor = SEVERITY_RANK[level]
  const shown: Shown[] = []
  if (health.noEnvButExample) {
    shown.push({
      scope: 'project', code: 'no-env', severity: 'warn',
      message: 'no .env, though .env.example declares keys', fix: 'warden init, then warden missing',
    })
  }
  for (const [scope, problems] of [['project', health.project], ['global', health.global]] as const) {
    for (const p of problems ?? []) {
      if (SEVERITY_RANK[p.severity] >= floor && !isMeantUnset(scope, p)) shown.push({ ...p, scope })
    }
  }
  return shown.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
}

// Identifies a set of findings, so a dismissal holds until something changes.
// Built from codes and key names only.
export function fingerprint(shown: readonly Shown[]): string {
  return shown.map(p => `${p.scope}:${p.code}:${p.key ?? ''}`).sort().join('|')
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`
}

export function summary(shown: readonly Shown[]): string {
  const project = shown.filter(p => p.scope === 'project').length
  const global = shown.filter(p => p.scope === 'global').length
  const parts: string[] = []
  if (project > 0) parts.push(`.env: ${plural(project, 'problem')}`)
  if (global > 0) parts.push(`~/.secrets: ${plural(global, 'problem')}`)
  return parts.join(' · ')
}

function fit(text: string, width: number): string {
  if (width <= 0) return ''
  return text.length <= width ? text.padEnd(width) : `${text.slice(0, Math.max(0, width - 1))}…`
}

// One band row, sized to the columns the band has: severity, code, message,
// then the fix, which gives way first.
export function bandRow(p: Shown, columns: number): { label: string; message: string; fix: string } {
  const label = `  ${fit(p.severity, 6)} ${fit(p.code, 9)} `
  const room = Math.max(0, columns - label.length)
  const messageWidth = p.fix === undefined ? room : Math.min(room, Math.max(24, Math.floor(room * 0.55)))
  const message = fit(`${p.scope === 'global' ? '~/.secrets: ' : ''}${p.message}`, messageWidth)
  const fixRoom = room - messageWidth - 2
  const fix = p.fix === undefined || fixRoom < 8 ? '' : `  ${fit(p.fix, fixRoom).trimEnd()}`
  return { label, message, fix }
}

// Marks each row with the doctor codes that name its key. A project row left
// empty says `unset` and carries no badge for it.
export function withFlags(rows: readonly EnvRow[], problems: readonly Problem[], scope: Scope): EnvRow[] {
  const badged = problems.filter(p => p.severity !== 'info' && !isMeantEmpty(scope, p))
  return rows.map(row => ({
    ...row,
    flags: [...new Set(badged.filter(p => p.key === row.key).map(p => p.code))],
  }))
}

export function rowLabel(row: EnvRow, isSelected: boolean, keyWidth: number): string {
  const flags = row.flags.length > 0 ? `  ${row.flags.join(' ')}` : ''
  return `${isSelected ? '▸' : ' '} ${row.key.padEnd(keyWidth)}  ${row.class.padEnd(6)}  ${(row.set ? 'set' : 'unset').padEnd(5)}${flags}`
}

// The first line of a command's output, or `fallback` when it printed nothing.
// warden's output carries no value, so this is safe to show.
export function firstLine(text: string, fallback: string): string {
  return text.trim().split('\n')[0] || fallback
}

export function scopeArgs(scope: Scope): string[] {
  return scope === 'global' ? ['--global'] : []
}

// What "Ask Claude to fix" puts in the prompt box, unsent.
export const FIX_PROMPT =
  'warden doctor reports problems with this project\'s env. Run `warden doctor` and ' +
  '`warden doctor --global`, then fix what they report using warden commands only — ' +
  'never read .env or ~/.secrets. Leave a key that is empty in .env, or declared in ' +
  '.env.example and absent from .env, as it is; that is meant. For a secret I have to type, ' +
  'run `warden set --secret KEY` and I will fill in the dialog.'
