import type { On } from 'claude-code'
import { expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'

import { FIX_PROMPT } from '../hooks/health'
import { CWD, fakeWarden, PROBLEMS, world } from './world'
import type { FakeWarden, Seen, WorldOptions } from './world'

const SURFACES = ['terminal', 'desktop'] as const

const BAND = {
  plugin: 'warden',
  component: 'AbovePrompt' as const,
  props: {
    hasSurvey: false, isWorking: false, maxRows: 8, bodyColumns: 100,
    scroll: { offset: 0, bodyRows: 8 }, view: {},
  },
}

const PANE_PROPS = {
  title: 'env', isFocused: true, bodyColumns: 90, placement: 'dock' as const,
  scroll: { offset: 0, bodyRows: 30 }, view: {},
}

// Another plugin's band beneath warden's: it must still show.
function otherBand(on: On) {
  on('ui.render', { component: 'AbovePrompt' }, ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    return <Box><Text key="other">another plugin's band</Text></Box>
  })
}

async function begin($: Engine, on: On, options: WorldOptions = {}): Promise<Seen> {
  const seen = world(on, options)
  otherBand(on)
  on('tool.call', () => ({ result: 'ok' }))
  await $.session.start({ cwd: CWD, surface: 'terminal', isInteractive: true })
  return seen
}

// The model running a warden write, after which the mod checks again.
async function wardenWrite($: Engine) {
  await $.tool.call({ tool: 'Bash', command: 'warden set --secret STRIPE_SECRET' })
}

async function runEnv($: Engine, args: string) {
  return $.command.run({
    command: 'env', args, origin: { kind: 'composer' }, presentation: { isFullscreen: true, columns: 160 },
  } as Parameters<typeof $.command.run>[0])
}

for (const surface of SURFACES) {
  test(`${surface}: the band shows doctor's problems above the other bands, worst first`, async ($, on) => {
    await begin($, on, { warden: fakeWarden({ doctor: { project: PROBLEMS, global: [] } }) })
    const ui = await $.ui.mount({ ...BAND, surface })
    expect(await ui.find({ type: 'Text', text: /\.env: 2 problems/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /error\s+perms/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /multi-line/ })).toBe(undefined)
    expect(await ui.find({ type: 'Text', text: /another plugin's band/ })).toBeDefined()
    await ui.unmount()
  })

  test(`${surface}: with nothing wrong the band is only what is beneath it`, async ($, on) => {
    await begin($, on)
    const ui = await $.ui.mount({ ...BAND, surface })
    expect(await ui.find({ key: 'warden-hide' })).toBe(undefined)
    expect(await ui.find({ type: 'Text', text: /another plugin's band/ })).toBeDefined()
    await ui.unmount()
  })

  test(`${surface}: Hide holds until the findings change`, async ($, on) => {
    const w: FakeWarden = fakeWarden({ doctor: { project: [PROBLEMS[0]!], global: [] } })
    await begin($, on, { warden: w })
    const ui = await $.ui.mount({ ...BAND, surface })
    await ui.press({ key: 'warden-hide' })
    expect(await ui.find({ key: 'warden-hide' })).toBe(undefined)
    expect(await ui.find({ type: 'Text', text: /another plugin's band/ })).toBeDefined()

    w.doctor.project = [PROBLEMS[0]!, PROBLEMS[1]!]
    await wardenWrite($)
    expect(await ui.find({ key: 'warden-hide' })).toBeDefined()
    await ui.unmount()
  })

  test(`${surface}: Ask Claude fills the prompt and sends nothing`, async ($, on) => {
    const seen = await begin($, on, { warden: fakeWarden({ doctor: { project: PROBLEMS, global: [] } }) })
    const ui = await $.ui.mount({ ...BAND, surface })
    await ui.press({ key: 'warden-ask' })
    expect(seen.fills).toEqual([FIX_PROMPT])
    await ui.unmount()
  })

  test(`${surface}: a project with .env.example and no .env is told to run warden init`, async ($, on) => {
    await begin($, on, {
      warden: fakeWarden({ doctor: { project: 'no-env-file', global: [] } }),
      files: [`${CWD}/.env.example`],
    })
    const ui = await $.ui.mount({ ...BAND, surface })
    expect(await ui.find({ type: 'Text', text: /no \.env/ })).toBeDefined()
    await ui.unmount()
  })

  test(`${surface}: a project with neither stays quiet`, async ($, on) => {
    await begin($, on, { warden: fakeWarden({ doctor: { project: 'no-env-file', global: [] } }), files: [] })
    const ui = await $.ui.mount({ ...BAND, surface })
    expect(await ui.find({ key: 'warden-hide' })).toBe(undefined)
    await ui.unmount()
  })

  test(`${surface}: /env lists names, classes and state, and Set runs warden's prompted write`, async ($, on) => {
    const w = fakeWarden({
      doctor: { project: PROBLEMS, global: [] },
      list: {
        project: [
          { key: 'APP_NAME', class: 'public', set: true },
          { key: 'STRIPE_SECRET', class: 'secret', set: false },
        ],
        global: [],
      },
    })
    const seen = await begin($, on, { warden: w })
    const answered = await runEnv($, '')
    expect(answered.text).toContain('Opened the env pane')
    expect(seen.opened).toEqual(['warden-env'])

    const ui = await $.ui.mount({ plugin: 'warden', surface, component: 'Pane', requestId: 'warden-env', props: PANE_PROPS })
    expect((await ui.find({ key: 'row-1' }))?.text).toMatch(/STRIPE_SECRET\s+secret\s+unset\s+drift/)

    // A public key has no write button here; the pane never takes a value.
    expect(await ui.find({ key: 'set' })).toBe(undefined)
    await ui.press({ key: 'row-1' })
    await ui.press({ key: 'set' })

    const set = seen.runs.find(r => r.argv[1] === 'set')
    expect(set?.argv).toEqual(['warden', 'set', '--secret', 'STRIPE_SECRET'])
    expect(set?.stdin).toBe(undefined)
    expect(set?.timeoutMs ?? 0).toBeGreaterThanOrEqual(150_000)
    expect(seen.toasts).toContain('ok: STRIPE_SECRET set (secret) in .env')
    await ui.unmount()
  })

  test(`${surface}: Generate and the global scope pass their flags`, async ($, on) => {
    const w = fakeWarden({ list: { project: [], global: [{ key: 'GH_TOKEN', class: 'secret', set: true }] } })
    const seen = await begin($, on, { warden: w })
    await runEnv($, 'global')
    const ui = await $.ui.mount({ plugin: 'warden', surface, component: 'Pane', requestId: 'warden-env', props: PANE_PROPS })
    await ui.press({ key: 'generate' })
    expect(seen.runs.find(r => r.argv[1] === 'set')?.argv).toEqual(['warden', 'set', '--secret', 'GH_TOKEN', '--generate', '--global'])
    await ui.unmount()
  })

  test(`${surface}: a cancelled dialog says nothing changed`, async ($, on) => {
    const w = fakeWarden({ setExit: 3, list: { project: [{ key: 'API_TOKEN', class: 'secret', set: false }], global: [] } })
    const seen = await begin($, on, { warden: w })
    await runEnv($, '')
    const ui = await $.ui.mount({ plugin: 'warden', surface, component: 'Pane', requestId: 'warden-env', props: PANE_PROPS })
    await ui.press({ key: 'set' })
    expect(seen.toasts.at(-1)).toContain('API_TOKEN not changed')
    await ui.unmount()
  })

  test(`${surface}: off macOS the pane shows the command instead of a button`, async ($, on) => {
    const w = fakeWarden({ darwin: false, list: { project: [{ key: 'API_TOKEN', class: 'secret', set: false }], global: [] } })
    await begin($, on, { warden: w })
    await runEnv($, '')
    const ui = await $.ui.mount({ plugin: 'warden', surface, component: 'Pane', requestId: 'warden-env', props: PANE_PROPS })
    expect(await ui.find({ key: 'set' })).toBe(undefined)
    expect(await ui.find({ type: 'Text', text: /! warden set --secret API_TOKEN/ })).toBeDefined()
    await ui.unmount()
  })

  test(`${surface}: Why asks warden for the rule`, async ($, on) => {
    const w = fakeWarden({ list: { project: [{ key: 'STRIPE_SECRET', class: 'secret', set: true }], global: [] } })
    await begin($, on, { warden: w })
    await runEnv($, '')
    const ui = await $.ui.mount({ plugin: 'warden', surface, component: 'Pane', requestId: 'warden-env', props: PANE_PROPS })
    await ui.press({ key: 'why' })
    expect(await ui.find({ type: 'Text', text: /STRIPE_SECRET: name:\*SECRET\*/ })).toBeDefined()
    await ui.unmount()
  })
}

test('on a phone the pane offers no dialog it could not show', async ($, on) => {
  const w = fakeWarden({ list: { project: [{ key: 'API_TOKEN', class: 'secret', set: false }], global: [] } })
  await begin($, on, { warden: w })
  await runEnv($, '')
  const ui = await $.ui.mount({ plugin: 'warden', surface: 'mobile', component: 'Pane', requestId: 'warden-env', props: PANE_PROPS })
  expect(await ui.find({ key: 'set' })).toBe(undefined)
  await ui.unmount()
})

test('/env refresh reports the guard and the health', async ($, on) => {
  await begin($, on, { warden: fakeWarden({ doctor: { project: PROBLEMS, global: [] } }) })
  const answered = await runEnv($, 'refresh')
  expect(answered.text).toContain('warden 0.1.6 (abc1234, 2026-10-04) guards env reads')
  expect(answered.text).toContain('.env: 2 problems')
})

test('the pane footer counts denials and redactions', async ($, on) => {
  await begin($, on)
  await $.tool.call({ tool: 'Bash', command: 'cat ~/.secrets' })
  await runEnv($, '')
  const ui = await $.ui.mount({ plugin: 'warden', surface: 'terminal', component: 'Pane', requestId: 'warden-env', props: PANE_PROPS })
  expect(await ui.find({ type: 'Text', text: /1 denied/ })).toBeDefined()
  await ui.unmount()
})
