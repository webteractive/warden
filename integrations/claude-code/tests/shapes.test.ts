import { expect, test } from 'claude-code/testing'

import { degradedReason, guarded, isWardenWrite, mightNameEnvFile, parseGuardAnswer, payload } from '../hooks/guard'
import { bandRow, fingerprint, FIX_PROMPT, shownProblems, withFlags } from '../hooks/health'
import { marker, modelNote, personNote, redact } from '../hooks/shapes'
import { PROBLEMS } from './world'

// Fixtures are built at run time so this file never holds a token-shaped
// string that some other scanner would rightly flag.
const LIVE = ['sk', 'live', 'A1b2C3d4E5f6G7h8J9k0'].join('_')
const TEST = ['sk', 'test', 'A1b2C3d4E5f6G7h8J9k0'].join('_')
const GHP = `ghp_${'a1B2'.repeat(9)}`
const AWS = `AKIA${'ABCD1234EFGH5678'}`
const PEM = ['-----BEGIN RSA PRIVATE KEY-----', 'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn', '-----END RSA PRIVATE KEY-----'].join('\n')
const JWT = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', 'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'].join('.')

test('a live key is removed and named, a test key only named', () => {
  const out = redact(`STRIPE=${LIVE} and TEST=${TEST}`, 'live')
  expect(out.text).toBe(`STRIPE=${marker('shape:stripe-live')} and TEST=${TEST}`)
  expect(out.findings.map(f => f.rule)).toEqual(['shape:stripe-live', 'shape:stripe-test'])
  expect(out.redacted.map(f => f.rule)).toEqual(['shape:stripe-live'])
})

test('the redaction level decides what goes', () => {
  expect(redact(TEST, 'all').text).toBe(marker('shape:stripe-test'))
  expect(redact(LIVE, 'off').text).toBe(LIVE)
  expect(redact(LIVE, 'off').findings.length).toBe(1)
})

test('every live shape is caught, and a private key goes whole', () => {
  for (const [value, rule] of [[GHP, 'shape:github-pat'], [AWS, 'shape:aws-access-key'], [PEM, 'shape:pem-block']] as const) {
    const out = redact(`before ${value} after`, 'live')
    expect(out.text).toBe(`before ${marker(rule)} after`)
  }
  const escaped = PEM.split('\n').join('\\n')
  expect(redact(`TLS_KEY="${escaped}"`, 'live').text).toBe(`TLS_KEY="${marker('shape:pem-block')}"`)
})

test('a JWT is noted, not removed', () => {
  const out = redact(`Bearer ${JWT}`, 'live')
  expect(out.text).toBe(`Bearer ${JWT}`)
  expect(out.findings[0]?.rule).toBe('shape:jwt')
})

test('a URL keeps everything but its password', () => {
  const out = redact('DATABASE_URL=postgres://admin:hunter2pw@db.example.com:5432/app', 'live')
  expect(out.text).toBe(`DATABASE_URL=postgres://admin:${marker('shape:url-userinfo')}@db.example.com:5432/app`)
})

test('documentation and public material are not findings', () => {
  for (const text of [
    'DATABASE_URL=postgres://user:password@localhost:5432/app',
    'redis://default:${REDIS_PASSWORD}@cache:6379',
    'mysql://root:<password>@db/app',
    '-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBa\n-----END CERTIFICATE-----',
    'the prefix sk_live_ on its own is a mention',
    'MASK_LIVE_THING and gho_short',
  ]) {
    expect(redact(text, 'all').findings).toEqual([])
  }
})

test('a local database URL with a real-looking password is a test finding', () => {
  const out = redact('postgres://app:s3cr3tvalue@localhost/app', 'live')
  expect(out.findings[0]?.confidence).toBe('test')
  expect(out.redacted).toEqual([])
})

test('the model is told not to use --exposed for what it never saw, and to use it for what it holds', () => {
  const removed = redact(LIVE, 'live')
  const removedNote = modelNote(removed.findings, removed.redacted) ?? ''
  expect(removedNote).toContain('removed from this output before you saw it')
  expect(removedNote).toContain('do not use warden set --exposed')
  expect(removedNote).not.toContain(LIVE)

  const kept = redact(TEST, 'live')
  const keptNote = modelNote(kept.findings, kept.redacted) ?? ''
  expect(keptNote).toContain('warden set --exposed KEY VALUE is the honest channel')
  expect(keptNote).not.toContain(TEST)
  expect(modelNote([], [])).toBe(undefined)
})

test('the person is told what and where, never the value', () => {
  const out = redact(`${LIVE} ${GHP}`, 'live')
  const note = personNote('Bash', out.findings, out.redacted)
  expect(note).toContain('a Stripe live key (and 1 other kind) appeared in Bash output — redacted for the model')
  expect(note).not.toContain(LIVE)
  expect(note).not.toContain(GHP)
})

test('nothing the mod says claims to be security', () => {
  const out = redact(`${LIVE} ${TEST}`, 'live')
  const texts = [
    modelNote(out.findings, out.redacted) ?? '',
    personNote('Bash', out.findings, out.redacted),
    personNote('Bash', out.findings, []),
    degradedReason('warden was not found'),
    FIX_PROMPT,
  ]
  for (const text of texts) {
    for (const banned of ['secure', 'security boundary', 'prevents', 'protects you']) {
      expect(text.toLowerCase()).not.toContain(banned)
    }
  }
})

test('the guard picks each tool\'s own fields, and nothing for tools it has no opinion on', () => {
  expect(guarded('Read', { file_path: '/p/.env', offset: 3 })).toEqual({ tool: 'Read', input: { file_path: '/p/.env' } })
  expect(guarded('NotebookEdit', { notebook_path: '/p/n.ipynb', new_source: 'x' })?.input).toEqual({ notebook_path: '/p/n.ipynb' })
  expect(guarded('Grep', { pattern: 'X', glob: '.env*' })?.input).toEqual({ glob: '.env*' })
  expect(guarded('Monitor', { command: 'tail -f .env', timeout_ms: 1 })?.input).toEqual({ command: 'tail -f .env' })
  expect(guarded('LSP', { operation: 'hover', filePath: '/p/.env', line: 1, character: 1 })?.input).toEqual({ filePath: '/p/.env' })
  expect(guarded('WebFetch', { url: 'https://example.com/.env' })).toBe(undefined)
  expect(guarded('Grep', { pattern: '.env' })).toBe(undefined)
})

test('with warden unavailable, anything that might spell an env file is held', () => {
  for (const held of ['cat .env.local', 'cat .ENV', '/Users/me/.SECRETS', 'cat .e""nv', 'cat .\\env', "cat $'\\x2eenv'", 'cat .e*v', 'cat [.]env', 'cat .{e,x}nv']) {
    expect(mightNameEnvFile([held])).toBe(true)
  }
  for (const fine of ['ls -la', 'git status', 'npm test', 'cat README.md', undefined]) {
    expect(mightNameEnvFile([fine])).toBe(false)
  }
})

test('the payload is the tool and its fields, as written', () => {
  const g = guarded('Read', { file_path: '/p/.ENV', limit: 3 })
  if (g === undefined) throw new Error('expected a guarded call')
  expect(JSON.parse(payload(g))).toEqual({ tool_name: 'Read', tool_input: { file_path: '/p/.ENV' } })
})

test('a guard answer is trusted only when exit code and JSON agree', () => {
  expect(parseGuardAnswer(0, '{"decision":"allow"}')).toEqual({ decision: 'allow' })
  expect(parseGuardAnswer(2, '{"decision":"deny","target":"secrets","reason":"no"}')).toEqual({ decision: 'deny', target: 'secrets', reason: 'no' })
  expect(parseGuardAnswer(0, '')).toBe(undefined)
  expect(parseGuardAnswer(2, '{"decision":"allow"}')).toBe(undefined)
  expect(parseGuardAnswer(1, 'not json')).toBe(undefined)
})

test('warden writes are told apart from reads', () => {
  expect(isWardenWrite('warden set --secret K')).toBe(true)
  expect(isWardenWrite('cd app && ~/.local/bin/warden --project . unset OLD')).toBe(true)
  expect(isWardenWrite('warden classify K --set public')).toBe(true)
  expect(isWardenWrite('warden vault push stripe --to .')).toBe(true)
  expect(isWardenWrite('warden list --json')).toBe(false)
  expect(isWardenWrite('echo warden set')).toBe(false)
})

test('the band shows warn and worse, errors first, and a fingerprint names findings, not values', () => {
  const health = { project: PROBLEMS, global: [PROBLEMS[1]!], noEnvButExample: false, checkedAt: 0 }
  const shown = shownProblems(health, 'warn')
  expect(shown.map(p => `${p.scope}:${p.code}`)).toEqual(['project:perms', 'project:drift', 'global:drift'])
  expect(shownProblems(health, 'error').length).toBe(1)
  expect(fingerprint(shown)).toBe('global:drift:STRIPE_SECRET|project:drift:STRIPE_SECRET|project:perms:')
  expect(fingerprint([...shown].reverse())).toBe(fingerprint(shown))
  expect(shownProblems({ project: null, global: null, noEnvButExample: true, checkedAt: 0 }, 'warn')[0]?.code).toBe('no-env')
})

test('a band row fits the columns it is given', () => {
  const p = { ...PROBLEMS[1]!, scope: 'project' as const }
  for (const columns of [40, 80, 160]) {
    const row = bandRow(p, columns)
    expect((row.label + row.message + row.fix).length).toBeLessThanOrEqual(columns)
  }
})

test('rows carry the warn-level codes that name their key', () => {
  const rows = withFlags([{ key: 'STRIPE_SECRET', class: 'secret', set: false, flags: [] }, { key: 'TLS_KEY', class: 'secret', set: true, flags: [] }], PROBLEMS)
  expect(rows.map(r => r.flags)).toEqual([['drift'], []])
})

// Each of these spells a live value so that an anchored or word-bounded rule
// misses it, or leaves part of it behind.
test('a value is found however the text around it is escaped', () => {
  for (const [text, value] of [
    [`{"out":"line one\\n${LIVE}\\n"}`, LIVE],
    [`https://api.example.com/?key%3D${LIVE}`, LIVE],
    [`AWS:\\t${AWS}`, AWS],
    [`token=${GHP}_suffix`, GHP],
  ] as const) {
    const out = redact(text, 'live')
    expect(out.text).not.toContain(value)
    expect(out.redacted.length).toBe(1)
  }
})

test('every occurrence is removed, not just the first', () => {
  const out = redact(`${LIVE} and again ${LIVE}`, 'live')
  expect(out.text).toBe(`${marker('shape:stripe-live')} and again ${marker('shape:stripe-live')}`)
})

test('a password containing @ goes whole', () => {
  const out = redact('postgres://admin:p@ss@word@db.example.com/app', 'live')
  expect(out.text).toBe(`postgres://admin:${marker('shape:url-userinfo')}@db.example.com/app`)
})

test('PGP and encrypted PEM keys lose their bodies, not just their headers', () => {
  const pgp = ['-----BEGIN PGP PRIVATE KEY BLOCK-----', '', 'lQOYBGVsecretBODYxyz', '=AbCd', '-----END PGP PRIVATE KEY BLOCK-----'].join('\n')
  expect(redact(pgp, 'live').text).toBe(marker('shape:pem-block'))
  const encrypted = ['-----BEGIN RSA PRIVATE KEY-----', 'Proc-Type: 4,ENCRYPTED', 'DEK-Info: AES-128-CBC,0123456789ABCDEF', '', 'MIIEowIBAAKCAQEAsecretBODY'].join('\n')
  const out = redact(encrypted, 'live').text
  expect(out).not.toContain('secretBODY')
  expect(out).not.toContain('Proc-Type')
})

test('nothing past the first megabytes is let through', () => {
  const out = redact(`${'x'.repeat(5 * 1024 * 1024)} ${LIVE}`, 'live')
  expect(out.text.endsWith(marker('shape:stripe-live'))).toBe(true)
})
