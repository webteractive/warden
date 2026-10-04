import { atom, read, update } from 'claude-code'
import type { EngineInterface, PluginOptions, Register } from 'claude-code'

import type { EnvRow, GuardStatus, Health, LeakTally, PaneAction, PaneState, Problem, Scope, Severity } from '../types'
import {
  degradedReason, guarded, isWardenWrite, mentionsEnvFile, parseGuardAnswer, payload,
} from './guard'
import type { Guarded } from './guard'
import {
  bandRow, errorCode, fingerprint, firstLine, FIX_PROMPT, parseProblems, parseRows, rowLabel, scopeArgs,
  shownProblems, summary, withFlags,
} from './health'
import { modelNote, personNote, redact } from './shapes'
import type { Finding, Redaction } from './shapes'

// warden in Claude Code: a guard on reads of .env and ~/.secrets, a tripwire on
// credentials in tool output, a band for what `warden doctor` finds, and an
// /env pane. warden decides and holds the values; this module only asks it.
//
// This is a speed bump list plus a tripwire behind it, not containment: a
// command can read a file in ways no matcher enumerates.
//
// Everything that touches `$` lives in this file: the engine follows `$` only
// into functions declared beside the hooks that use it.

const PANE = 'warden-env'

const INITIAL_GUARD: GuardStatus = { mode: 'unknown', canPrompt: false, denies: { env: 0, secrets: 0 } }
const INITIAL_PANE: PaneState = { scope: 'project', rows: null, selected: null, pending: null, why: null }

const guardState = atom({ plugin: 'warden', key: 'guard' } as const, INITIAL_GUARD)
const leaks = atom({ plugin: 'warden', key: 'leaks' } as const, { total: 0, redacted: 0, byRule: {} } as LeakTally)
const health = atom({ plugin: 'warden', key: 'health' } as const, null as Health | null)
const bandHiddenFor = atom({ plugin: 'warden', key: 'bandHiddenFor' } as const, null as string | null)
const pane = atom({ plugin: 'warden', key: 'pane' } as const, INITIAL_PANE)

// How long a dialog-driven write may take: warden's Authorise dialog and its
// value dialog each give up after 60 s.
const PROMPT_TIMEOUT_MS = 180_000
const QUICK_TIMEOUT_MS = 10_000
// The turn.complete check runs at most this often.
const RECHECK_MS = 60_000
const TOAST_EVERY_MS = 60_000

type Config = { redact: Redaction; band: boolean; bandLevel: Severity; wardenPath: string }

function config(options: PluginOptions): Config {
  const o = options as Record<string, unknown>
  const redactLevel = o.redact === 'all' || o.redact === 'off' ? o.redact : 'live'
  return {
    redact: redactLevel,
    band: o.band !== false,
    bandLevel: o.bandLevel === 'error' ? 'error' : 'warn',
    wardenPath: typeof o.wardenPath === 'string' ? o.wardenPath : '',
  }
}

// Module state. A reload starts it over, and session.start fires again on a
// reload, so the probe reruns; nothing here has to survive one.
let cfg: Config = config({})
let probing: Promise<GuardStatus> | undefined
let checking: Promise<void> | undefined
let lastCheck = 0
const lastToast = new Map<string, number>()

type Ran = { exitCode: number; stdout: string; stderr: string }

async function run(
  $: EngineInterface, args: readonly string[], init: { stdin?: string; timeoutMs?: number; cwd?: string } = {},
): Promise<Ran> {
  const status = await read($, guardState)
  const bin = status.binary ?? 'warden'
  try {
    const ran = await $.process.run([bin, ...args], { timeoutMs: QUICK_TIMEOUT_MS, ...init })
    return { exitCode: ran.exitCode, stdout: ran.stdout, stderr: ran.stderr }
  } catch (err) {
    return { exitCode: -1, stdout: '', stderr: String(err) }
  }
}

// Finds warden and checks it can run the guard this mod depends on. A binary
// that cannot (missing, or older than `hook --guard --json`) leaves the guard
// degraded, which denies only calls that name an env file.
async function probe($: EngineInterface): Promise<GuardStatus> {
  const home = await $.env.get('HOME')
  const candidates = cfg.wardenPath !== ''
    ? [cfg.wardenPath]
    : ['warden', ...(home === undefined ? [] : [`${home}/.local/bin/warden`])]

  let reason = 'warden was not found on PATH or in ~/.local/bin'
  for (const bin of candidates) {
    let version: Ran
    try {
      const ran = await $.process.run([bin, '--version'], { timeoutMs: QUICK_TIMEOUT_MS })
      version = { exitCode: ran.exitCode, stdout: ran.stdout, stderr: ran.stderr }
    } catch {
      continue
    }
    if (version.exitCode !== 0) {
      reason = `${bin} is too old to report its version; reinstall it`
      continue
    }
    let answer
    try {
      const ran = await $.process.run([bin, 'hook', '--guard', '--json'], { stdin: '{}', timeoutMs: QUICK_TIMEOUT_MS })
      answer = parseGuardAnswer(ran.exitCode, ran.stdout)
    } catch {
      answer = undefined
    }
    if (answer?.decision !== 'allow') {
      reason = `${bin} is too old to run hook --guard --json; reinstall it`
      continue
    }
    const canPrompt = await isMac($)
    const now = await read($, guardState)
    return {
      ...now,
      mode: 'warden',
      binary: bin,
      version: version.stdout.trim().replace(/^warden\s+/, ''),
      reason: undefined,
      canPrompt,
    }
  }
  const now = await read($, guardState)
  return { ...now, mode: 'degraded', binary: undefined, version: undefined, reason, canPrompt: false }
}

async function isMac($: EngineInterface): Promise<boolean> {
  try {
    const ran = await $.process.run(['uname', '-s'], { timeoutMs: QUICK_TIMEOUT_MS })
    return ran.stdout.trim() === 'Darwin'
  } catch {
    return false
  }
}

// One probe at a time; `force` reruns it (/env refresh).
async function ensureProbe($: EngineInterface, force = false): Promise<GuardStatus> {
  const known = await read($, guardState)
  if (!force && known.mode !== 'unknown') return known
  probing ??= probe($)
    .then(async status => {
      await update($, guardState, () => status)
      $.ui.status(status.mode === 'degraded' ? 'warden: guard degraded' : undefined)
      if (status.mode === 'degraded') $.ui.toast(`warden: guard degraded — ${status.reason ?? 'warden unavailable'}`)
      return status
    })
    .finally(() => {
      probing = undefined
    })
  return probing
}

async function countDeny($: EngineInterface, target: 'env' | 'secrets'): Promise<void> {
  await update($, guardState, s => ({ ...s, denies: { ...s.denies, [target]: s.denies[target] + 1 } }))
}

// Returns the denial for a guarded call, or undefined to let it run.
async function judge($: EngineInterface, g: Guarded): Promise<string | undefined> {
  // `ln -s .env notes.txt` then `Read notes.txt`: warden judges spellings, so
  // the resolved path is asked about as well.
  let real: string | undefined
  if (g.path !== undefined) {
    try {
      const stat = await $.fs.stat(g.path, { resolve: true })
      if (stat.realPath !== undefined && stat.realPath !== g.path) real = stat.realPath
    } catch {
      real = undefined
    }
  }
  if (!mentionsEnvFile([...Object.values(g.input), real])) return undefined

  const status = await ensureProbe($)
  if (status.mode !== 'warden') {
    await countDeny($, /\.secrets/.test(JSON.stringify(g.input) + (real ?? '')) ? 'secrets' : 'env')
    return degradedReason(status.reason ?? 'warden unavailable')
  }
  for (const body of real === undefined ? [payload(g)] : [payload(g), payload(g, real)]) {
    const ran = await run($, ['hook', '--guard', '--json'], { stdin: body })
    const answer = parseGuardAnswer(ran.exitCode, ran.stdout)
    if (answer === undefined) return degradedReason('the guard gave no answer')
    if (answer.decision === 'deny') {
      await countDeny($, answer.target ?? 'env')
      return answer.reason
    }
  }
  return undefined
}

type Block = { type: string; [field: string]: unknown }

// Scans one row's text and tool_result content, redacting what the level
// covers. Returns undefined when nothing was found. Nothing is exempt, warden's
// own output included: warden never prints a value, so a hit there is an
// anomaly worth reporting, and "this came from warden" is what a command
// substitution, a redirect or a binary merely named warden can fake.
function scanRow(content: readonly Block[]): { content: Block[]; findings: Finding[]; redacted: Finding[] } | undefined {
  const findings: Finding[] = []
  const redacted: Finding[] = []
  const scanText = (text: string): string => {
    const scanned = redact(text, cfg.redact)
    findings.push(...scanned.findings)
    redacted.push(...scanned.redacted)
    return scanned.text
  }
  const out = content.map((block): Block => {
    if (block.type === 'text' && typeof block.text === 'string') return { ...block, text: scanText(block.text) }
    if (block.type !== 'tool_result') return block
    if (typeof block.content === 'string') return { ...block, content: scanText(block.content) }
    if (Array.isArray(block.content)) {
      return {
        ...block,
        content: (block.content as Block[]).map(inner =>
          inner.type === 'text' && typeof inner.text === 'string' ? { ...inner, text: scanText(inner.text) } : inner),
      }
    }
    return block
  })
  return findings.length === 0 ? undefined : { content: out, findings, redacted }
}

async function tally($: EngineInterface, findings: readonly Finding[], redacted: readonly Finding[]): Promise<void> {
  await update($, leaks, t => {
    const byRule = { ...t.byRule }
    for (const f of findings) byRule[f.rule] = (byRule[f.rule] ?? 0) + 1
    return { total: t.total + findings.length, redacted: t.redacted + redacted.length, byRule }
  })
}

// Tells the person: a transcript notice each time, a toast at most once a
// minute per rule. Neither carries a value.
async function tellPerson($: EngineInterface, tool: string, findings: readonly Finding[], redacted: readonly Finding[]): Promise<void> {
  const note = personNote(tool, findings, redacted)
  $.ui.log(note)
  const now = await $.clock.now()
  const rule = (redacted[0] ?? findings[0])?.rule ?? ''
  if (now - (lastToast.get(rule) ?? -Infinity) >= TOAST_EVERY_MS) {
    lastToast.set(rule, now)
    $.ui.toast(note, { timeoutMs: 8_000 })
  }
}

type Doctor = { problems: Problem[] | null; noEnv: boolean; error?: string }

async function doctor($: EngineInterface, scope: Scope, cwd: string): Promise<Doctor> {
  const ran = await run($, ['doctor', '--json', ...scopeArgs(scope)], { cwd })
  if (ran.exitCode === 0) {
    const problems = parseProblems(ran.stdout)
    return problems === undefined ? { problems: null, noEnv: false, error: 'unreadable doctor output' } : { problems, noEnv: false }
  }
  if (errorCode(ran.stderr) === 'no-env-file') return { problems: null, noEnv: true }
  return { problems: null, noEnv: false, error: firstLine(ran.stderr, `exit ${ran.exitCode}`) }
}

async function exists($: EngineInterface, path: string): Promise<boolean> {
  try {
    return (await $.fs.stat(path)).kind === 'file'
  } catch {
    return false
  }
}

async function runCheck($: EngineInterface): Promise<void> {
  const status = await ensureProbe($)
  const now = await $.clock.now()
  lastCheck = now
  if (status.mode !== 'warden') {
    await update($, health, () => ({ project: null, global: null, noEnvButExample: false, checkedAt: now, error: status.reason }))
    return
  }
  const cwd = await $.session.cwd()
  const [project, global] = await Promise.all([doctor($, 'project', cwd), doctor($, 'global', cwd)])
  // A project with no .env says nothing, unless .env.example says it should
  // have one. A stat of the example reads nothing protected.
  const noEnvButExample = project.noEnv && (await exists($, `${cwd}/.env.example`))
  const error = project.error ?? global.error
  await update($, health, () => ({
    project: project.problems,
    global: global.problems,
    noEnvButExample,
    checkedAt: now,
    ...(error === undefined ? {} : { error }),
  }))
}

// One check at a time; a second request while one runs waits for it.
function checkHealth($: EngineInterface): Promise<void> {
  checking ??= runCheck($).finally(() => {
    checking = undefined
  })
  return checking
}

async function loadPane($: EngineInterface, scope?: Scope): Promise<void> {
  const current = await read($, pane)
  const target = scope ?? current.scope
  const cwd = await $.session.cwd()
  const [listed, problems] = await Promise.all([
    run($, ['list', '--json', ...scopeArgs(target)], { cwd }),
    doctor($, target, cwd),
  ])
  const rows = listed.exitCode === 0 ? parseRows(listed.stdout) : undefined
  const error = rows !== undefined ? undefined
    : errorCode(listed.stderr) === 'no-env-file'
      ? (target === 'global' ? 'There is no ~/.secrets. Create it with warden init --global.' : 'This project has no .env. Create it with warden init.')
      : firstLine(listed.stderr, 'warden did not answer')
  await update($, pane, s => ({
    ...s,
    scope: target,
    rows: rows === undefined ? null : withFlags(rows, problems.problems ?? []),
    selected: s.scope === target && rows?.some(r => r.key === s.selected) ? s.selected : rows?.[0]?.key ?? null,
    why: s.scope === target ? s.why : null,
    ...(error === undefined ? { error: undefined } : { error }),
  }))
}

async function openPane($: EngineInterface, scope: Scope): Promise<void> {
  await ensureProbe($)
  await loadPane($, scope)
  await $.ui.open({ id: PANE, title: 'env' })
}

// Runs warden's own prompted write. No value is passed or seen: warden opens
// its dialog, the person types, and warden reports `ok: KEY set …`.
async function write($: EngineInterface, key: string, action: PaneAction): Promise<void> {
  const state = await read($, pane)
  if (state.pending !== null) return
  await update($, pane, s => ({ ...s, pending: { key, action } }))
  try {
    const args = ['set', '--secret', key, ...(action === 'generate' ? ['--generate'] : []), ...scopeArgs(state.scope)]
    const ran = await run($, args, { timeoutMs: PROMPT_TIMEOUT_MS, cwd: await $.session.cwd() })
    const said = ran.exitCode === 0
      ? firstLine(ran.stdout, `ok: ${key}`)
      : ran.exitCode === 3 ? `warden: ${key} not changed (cancelled, or the dialog could not be shown)`
        : firstLine(ran.stderr, `warden exited ${ran.exitCode}`)
    $.ui.toast(said)
  } finally {
    await update($, pane, s => ({ ...s, pending: null }))
  }
  await loadPane($).catch(() => {})
  await checkHealth($).catch(() => {})
}

async function why($: EngineInterface, key: string): Promise<void> {
  const state = await read($, pane)
  const ran = await run($, ['classify', key, '--json', ...scopeArgs(state.scope)], { cwd: await $.session.cwd() })
  let rule = 'unknown'
  try {
    const parsed = JSON.parse(ran.stdout) as { rule?: unknown }
    if (typeof parsed.rule === 'string') rule = parsed.rule
  } catch {
    rule = 'warden did not answer'
  }
  await update($, pane, s => ({ ...s, why: { key, rule } }))
}

export const register: Register = (on, options) => {
  cfg = config(options)

  // MARK: - Guard

  // One unmatched tool.call hook: the guard before the call, the health
  // refresh after it. Subagents' calls come
  // through here too (they carry agentId).
  on('tool.call', async ($, e, next) => {
    const tool = String(e.tool)
    const fields = e as unknown as Readonly<Record<string, unknown>>
    const g = guarded(tool, fields)
    if (g !== undefined) {
      const denial = await judge($, g)
      if (denial !== undefined) return { deny: denial }
    }

    const command = tool === 'Bash' && typeof fields.command === 'string' ? fields.command : ''
    const ran = await next(e)
    if (command !== '' && isWardenWrite(command)) {
      await checkHealth($).catch(() => {})
      if ((await $.ui.panes()).some(p => p.id === PANE)) await loadPane($).catch(() => {})
    }
    return ran
  })

  // MARK: - Tripwire

  // One unmatched hook: the rows a tool produces are the ones scanned, in the
  // main conversation and every subagent's alike. Rewriting here is before the
  // row is stored and before the next request carries it.
  on('session.append', async ($, e, next) => {
    if (e.door !== 'tool-result' && e.door !== 'tool-message') return next(e)
    const scanned = scanRow(e.message.content as Block[])
    if (scanned === undefined) return next(e)
    const tool = e.origin.kind === 'tool' ? e.origin.tool : 'tool'
    const note = modelNote(scanned.findings, scanned.redacted)
    const content = note === undefined ? scanned.content : [...scanned.content, { type: 'text', text: note }]
    await tally($, scanned.findings, scanned.redacted)
    await tellPerson($, tool, scanned.findings, scanned.redacted)
    return next({ ...e, message: { ...e.message, content } })
  })

  // MARK: - Health

  on('classic.CwdChanged', async ($, e, next) => {
    const result = await next(e)
    await checkHealth($).catch(() => {})
    return result
  })

  // Catches edits made outside the session, at most once a minute.
  on('turn.complete', async ($, e, next) => {
    const result = await next(e)
    if (e.agentId === undefined && (await $.clock.now()) - lastCheck >= RECHECK_MS) {
      await checkHealth($).catch(() => {})
    }
    return result
  })

  // The band is one instance every plugin draws into. What the hooks beneath
  // drew stays, under warden's rows, so other bands are never hidden.
  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e)
    const below = await next(e)
    if (!cfg.band) return below
    const shown = shownProblems(await read($, health), cfg.bandLevel)
    if (shown.length === 0 || (await read($, bandHiddenFor)) === fingerprint(shown)) return below

    const { Box, Button, Text } = $.ui.resolve(e)
    const room = Math.max(1, Math.min(3, e.props.maxRows - 2))
    const columns = e.props.bodyColumns
    const more = shown.length - room

    return (
      <Box flexDirection="column">
        <Box key="warden-head">
          <Text bold>warden </Text>
          <Text>{summary(shown)} </Text>
          <Button key="warden-open" label="Open /env" onPress={() => openPane($, 'project')} />
          <Button key="warden-ask" label="Ask Claude to fix" onPress={async () => { await $.prompt.fill({ text: FIX_PROMPT }) }} />
          <Button key="warden-hide" label="Hide" onPress={() => update($, bandHiddenFor, () => fingerprint(shown))} />
        </Box>
        {shown.slice(0, room).map((p, index) => {
          const row = bandRow(p, columns)
          return (
            <Box key={`warden-row-${index}`}>
              <Text color={p.severity === 'error' ? 'red' : 'yellow'} wrap="truncate">{row.label}</Text>
              <Text wrap="truncate">{row.message}</Text>
              <Text dimColor wrap="truncate">{row.fix}</Text>
            </Box>
          )
        })}
        {more > 0 && <Text key="warden-more" dimColor>{`  … ${more} more in /env`}</Text>}
        {below}
      </Box>
    )
  })

  // MARK: - /env pane

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Button, Text } = $.ui.resolve(e)
    const state = await read($, pane)
    const status = await read($, guardState)
    const found = await read($, leaks)
    const rows = state.rows ?? []
    const keyWidth = Math.min(32, Math.max(8, ...rows.map(r => r.key.length)))
    const selected: EnvRow | undefined = rows.find(r => r.key === state.selected)
    // warden's dialog shows on this Mac's screen; a phone looking at the
    // session would never see it.
    const canWrite = status.canPrompt && e.surface !== 'mobile'

    return (
      <Box flexDirection="column">
        <Box key="scopes">
          <Button key="scope-project" label="Project" variant={state.scope === 'project' ? 'primary' : 'secondary'} onPress={() => loadPane($, 'project')} />
          <Button key="scope-global" label="Global" variant={state.scope === 'global' ? 'primary' : 'secondary'} onPress={() => loadPane($, 'global')} />
          <Text dimColor>{state.scope === 'global' ? ' ~/.secrets' : ' this project\'s .env'} — names only, never values</Text>
        </Box>
        {state.error !== undefined && <Text key="error" color="yellow">{state.error}</Text>}
        {state.rows !== null && rows.length === 0 && <Text key="empty" dimColor>No keys.</Text>}
        {rows.map((row, index) => (
          <Button
            key={`row-${index}`}
            plain
            label={rowLabel(row, row.key === state.selected, keyWidth)}
            onPress={() => update($, pane, s => ({ ...s, selected: row.key, why: null }))}
          />
        ))}
        {selected !== undefined && (
          <Box key="actions">
            <Text bold>{selected.key} </Text>
            {state.pending !== null && <Text color="yellow">waiting for the dialog on your screen…</Text>}
            {state.pending === null && selected.class === 'secret' && canWrite && (
              <Box>
                <Button key="set" label="Set…" onPress={() => write($, selected.key, 'set')} />
                <Button key="generate" label="Generate" onPress={() => write($, selected.key, 'generate')} />
              </Box>
            )}
            {state.pending === null && selected.class === 'secret' && !canWrite && (
              <Text dimColor>{`run: ! warden set --secret ${selected.key}${state.scope === 'global' ? ' --global' : ''}`}</Text>
            )}
            {state.pending === null && selected.class === 'public' && (
              <Text dimColor>{`ask Claude: warden set ${selected.key} VALUE`}</Text>
            )}
            {state.pending === null && <Button key="why" label="Why" onPress={() => why($, selected.key)} />}
          </Box>
        )}
        {state.why !== null && state.why.key === state.selected && (
          <Text key="why-line" dimColor>{`  ${state.why.key}: ${state.why.rule}`}</Text>
        )}
        {selected?.class === 'secret' && canWrite && state.pending === null && (
          <Text key="hint" dimColor>  Set… opens warden's dialog; the value never reaches this pane.</Text>
        )}
        <Box key="footer">
          <Text dimColor>
            {status.mode === 'warden' ? `guard: warden ${status.version ?? ''}` : `guard: ${status.mode}`}
            {` · ${status.denies.env + status.denies.secrets} denied · tripwire: ${found.redacted} redacted, ${found.total} found `}
          </Text>
          <Button key="refresh" label="Refresh" onPress={() => loadPane($)} />
          <Button key="close" label="Close" role="dismiss" onPress={() => $.ui.close({ id: PANE })} />
        </Box>
      </Box>
    )
  })

  on('command.run', { command: 'env' }, async ($, e) => {
    const verb = e.args.trim()
    if (verb === 'refresh') {
      const status = await ensureProbe($, true)
      await checkHealth($)
      if ((await $.ui.panes()).some(p => p.id === PANE)) await loadPane($)
      const shown = shownProblems(await read($, health), cfg.bandLevel)
      const guardLine = status.mode === 'warden' ? `warden ${status.version ?? ''} guards env reads` : `guard degraded: ${status.reason ?? ''}`
      return { text: `${guardLine}. ${shown.length === 0 ? 'No env problems.' : summary(shown)}` }
    }
    if (verb !== '' && verb !== 'global') return { text: 'Usage: /env [global|refresh]' }
    const scope: Scope = verb === 'global' ? 'global' : 'project'
    await openPane($, scope)
    return { text: `Opened the env pane (${scope === 'global' ? '~/.secrets' : 'this project'}).` }
  })

  // MARK: - Start

  on('session.start', async ($, e, next) => {
    const started = await next(e)
    await $.command.register({
      name: 'env',
      description: 'Keys, classes and health of this project\'s env — never values',
      argumentHint: '[global|refresh]',
    }).catch(() => {})
    await ensureProbe($, true).catch(() => {})
    await checkHealth($).catch(() => {})
    return started
  })
}
