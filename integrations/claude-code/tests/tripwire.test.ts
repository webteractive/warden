import { expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'

import { CWD, world } from './world'
import type { Seen } from './world'

const LIVE = ['sk', 'live', 'Z9y8X7w6V5u4T3s2R1q0'].join('_')
const TEST = ['sk', 'test', 'Z9y8X7w6V5u4T3s2R1q0'].join('_')

type Block = { type: string; [field: string]: unknown }

// Appends a tool result and returns the row as the mod handed it down.
async function appendResult($: Engine, seen: Seen, content: string | Block[], tool = 'Bash', toolUseId = 'toolu_1') {
  await $.session.append({
    message: { type: 'user', role: 'user', content: [{ type: 'tool_result', tool_use_id: toolUseId, content }] },
    door: 'tool-result',
    origin: { kind: 'tool', tool },
    uuid: `row-${toolUseId}`,
  }).catch(() => undefined)
  return seen.stored.at(-1) as { content: Block[] }
}

async function start($: Engine) {
  await $.session.start({ cwd: CWD, surface: 'terminal', isInteractive: true })
}

test('a live key in a tool result is redacted before it is stored, and the model is told why', async ($, on) => {
  const seen = world(on)
  await start($)
  const stored = await appendResult($, seen, `STRIPE_SECRET=${LIVE}\n`)
  const text = JSON.stringify(stored)
  expect(text).not.toContain(LIVE)
  expect(text).toContain('[warden: redacted shape:stripe-live]')
  expect(text).toContain('do not use warden set --exposed')
})

test('the person gets a toast and a transcript line, and neither holds the value', async ($, on) => {
  const seen = world(on)
  await start($)
  await appendResult($, seen, `key ${LIVE}`)
  expect(seen.toasts.some(t => t.includes('a Stripe live key appeared in Bash output'))).toBe(true)
  expect(seen.logs.some(l => l.includes('redacted for the model'))).toBe(true)
  for (const said of [...seen.toasts, ...seen.logs, ...seen.statuses]) expect(said).not.toContain(LIVE)
})

test('a test key is noted for the model but left in place', async ($, on) => {
  const seen = world(on)
  await start($)
  const stored = await appendResult($, seen, [{ type: 'text', text: `STRIPE_KEY=${TEST}` }])
  const text = JSON.stringify(stored)
  expect(text).toContain(TEST)
  expect(text).toContain('warden set --exposed KEY VALUE is the honest channel')
})

test('a clean result is stored as it came', async ($, on) => {
  const seen = world(on)
  await start($)
  const stored = await appendResult($, seen, 'total 0\n')
  expect(stored.content).toEqual([{ type: 'tool_result', tool_use_id: 'toolu_1', content: 'total 0\n' }])
})

// A command that looks like warden's own is scanned like any other. warden
// never prints a value, so a hit in its output is an anomaly worth reporting —
// and "looks like warden" is exactly what a substitution, a redirect or a
// binary merely named warden can fake.
const LOOKALIKES = [
  'warden doctor',
  'warden classify X $(cat creds.txt)',
  'warden classify X `cat creds.txt`',
  'warden list --file <(cat creds.txt)',
  'warden list > out.txt; warden doctor',
  '/tmp/x/warden list',
  './evil/warden doctor',
  'warden list && warden doctor',
]

for (const [index, command] of LOOKALIKES.entries()) {
  test(`output of \`${command}\` is scanned`, async ($, on) => {
    const seen = world(on)
    on('tool.call', () => ({ result: 'ok' }))
    await start($)
    const id = `toolu_look_${index}`
    await $.tool.call({ tool: 'Bash', command, tool_use_id: id } as Parameters<typeof $.tool.call>[0])
    const stored = await appendResult($, seen, `output ${LIVE}`, 'Bash', id)
    expect(JSON.stringify(stored)).not.toContain(LIVE)
    expect(seen.toasts.some(t => t.includes('Stripe live key'))).toBe(true)
  })
}

test('a toast for the same kind is shown once a minute, the transcript line every time', async ($, on) => {
  const seen = world(on)
  await start($)
  await appendResult($, seen, LIVE, 'Bash', 'toolu_a')
  await appendResult($, seen, LIVE, 'Bash', 'toolu_b')
  expect(seen.toasts.filter(t => t.includes('Stripe live key')).length).toBe(1)
  expect(seen.logs.filter(l => l.includes('Stripe live key')).length).toBe(2)
})

test('rows that are not tool output are left alone', async ($, on) => {
  const seen = world(on)
  await start($)
  await $.session.append({
    message: { type: 'user', role: 'user', content: [{ type: 'text', text: `my key is ${LIVE}` }] },
    door: 'prompt',
    origin: { kind: 'composer' },
    uuid: 'row-prompt',
  } as Parameters<typeof $.session.append>[0]).catch(() => undefined)
  expect(JSON.stringify(seen.stored.at(-1))).toContain(LIVE)
  expect(seen.toasts).toEqual([])
})
