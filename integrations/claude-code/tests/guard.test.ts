import type { On } from 'claude-code'
import { expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'

import { CWD, fakeWarden, guardRuns, world } from './world'
import type { WorldOptions } from './world'

// What the tool itself returns when the call gets that far: the test's own
// hook stands beneath the mod, where the tool would run.
function tools(on: On, ran: string[]) {
  on('tool.call', (_$, e) => {
    ran.push(String(e.tool))
    return { result: 'tool ran' }
  })
}

async function start($: Engine) {
  await $.session.start({ cwd: CWD, surface: 'terminal', isInteractive: true })
}

async function setup($: Engine, on: On, options: WorldOptions = {}) {
  const seen = world(on, options)
  const ran: string[] = []
  tools(on, ran)
  await start($)
  return { seen, ran }
}

test('a read of .env is denied with warden\'s own reason, and the tool never runs', async ($, on) => {
  const { seen, ran } = await setup($, on)
  const result = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
  expect(result.deny).toContain('Denied: reading .env directly')
  expect(result.deny).toContain('warden has KEY')
  expect(ran).toEqual([])
  expect(guardRuns(seen).at(-1)?.argv).toEqual(['warden', 'hook', '--guard', '--json'])
  expect(JSON.parse(guardRuns(seen).at(-1)?.stdin ?? '')).toEqual({ tool_name: 'Bash', tool_input: { command: 'cat .env' } })
})

test('a call that names no env file runs without asking warden', async ($, on) => {
  const { seen, ran } = await setup($, on)
  const result = await $.tool.call({ tool: 'Bash', command: 'ls -la' })
  expect(result.deny).toBe(undefined)
  expect(ran).toEqual(['Bash'])
  expect(guardRuns(seen)).toEqual([])
})

test('the example file is asked about and allowed', async ($, on) => {
  const { ran } = await setup($, on)
  const result = await $.tool.call({ tool: 'Read', file_path: '/work/app/.env.example' })
  expect(result.deny).toBe(undefined)
  expect(ran).toEqual(['Read'])
})

test('a symlink to .env is denied by where it lands', async ($, on) => {
  const { seen, ran } = await setup($, on, { links: { '/work/app/notes.txt': '/work/app/.env' } })
  const result = await $.tool.call({ tool: 'Read', file_path: '/work/app/notes.txt' })
  expect(result.deny).toContain('Denied')
  expect(ran).toEqual([])
  expect(guardRuns(seen).map(r => JSON.parse(r.stdin ?? '').tool_input.file_path)).toEqual([
    '/work/app/notes.txt', '/work/app/.env',
  ])
})

test('~/.secrets is denied, and its target reaches warden\'s answer', async ($, on) => {
  const { ran } = await setup($, on)
  const result = await $.tool.call({ tool: 'Bash', command: 'source ~/.secrets' })
  expect(result.deny).toContain('Denied: reading .secrets directly')
  expect(ran).toEqual([])
})

test('a subagent\'s call is guarded like the main loop\'s', async ($, on) => {
  const { ran } = await setup($, on)
  const result = await $.tool.call({ tool: 'Bash', command: 'head .env', agentId: 'agent-1' } as Parameters<typeof $.tool.call>[0])
  expect(result.deny).toContain('Denied')
  expect(ran).toEqual([])
})

test('with no warden, calls naming an env file are held and the rest run untouched', async ($, on) => {
  const { seen, ran } = await setup($, on, { warden: fakeWarden({ installed: false }) })
  const denied = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
  expect(denied.deny).toContain('warden is not runnable here')
  const fine = await $.tool.call({ tool: 'Bash', command: 'ls' })
  expect(fine.deny).toBe(undefined)
  expect(ran).toEqual(['Bash'])
  expect(seen.statuses).toContain('warden: guard degraded')
})

test('a warden too old for --json leaves the guard degraded rather than trusted', async ($, on) => {
  const { ran } = await setup($, on, { warden: fakeWarden({ json: false }) })
  const result = await $.tool.call({ tool: 'Read', file_path: '/work/app/.env' })
  expect(result.deny).toContain('too old to run hook --guard --json')
  expect(ran).toEqual([])
})

test('warden found only in ~/.local/bin is used from there', async ($, on) => {
  const { seen } = await setup($, on)
  await $.tool.call({ tool: 'Bash', command: 'cat .env' })
  // The fake answers both spellings; the first that runs is kept.
  expect(guardRuns(seen).at(-1)?.argv[0]).toBe('warden')
})

test('a warden write refreshes the health check', async ($, on) => {
  const { seen } = await setup($, on)
  const before = seen.runs.filter(r => r.argv[1] === 'doctor').length
  await $.tool.call({ tool: 'Bash', command: 'warden set --secret STRIPE_SECRET' })
  expect(seen.runs.filter(r => r.argv[1] === 'doctor').length).toBe(before + 2)
})
