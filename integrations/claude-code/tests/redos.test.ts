import { expect, test } from 'claude-code/testing'

import { redact } from '../hooks/shapes'

// Tool results can be megabytes, so every rule must be linear. Each input is
// about 1 MB and built to make a backtracking rule try every start position
// and fail late: almost a prefix, almost a JWT, almost a URL, almost a key.
const MB = 1024 * 1024
const fill = (unit: string) => unit.repeat(Math.ceil(MB / unit.length))

const ADVERSARIAL: ReadonlyArray<readonly [string, string]> = [
  ['eyJ repeated', fill('eyJ')],
  ['two JWT parts, never three', fill('eyJabcdefghijkl.eyJabcdefghijkl!')],
  ['dotted words that look like schemes', fill('a.')],
  ['schemes with no host', fill('a://u:')],
  ['passwords with no host', 'x://u:' + fill('p@')],
  ['BEGIN headers with no END, fenced', fill('-----BEGIN PRIVATE KEY-----!')],
  ['BEGIN with a label that never ends', '-----BEGIN ' + fill('A')],
  ['END markers with no BEGIN', fill('-----END PRIVATE KEY-----')],
  ['BEGIN and END alternating with mismatched labels', fill('-----BEGIN A PRIVATE KEY----- x -----END B PRIVATE KEY-----!')],
  ['a JWT-shaped run after every escaped newline', fill('\\neyJabcdefghijkl')],
  ['base64-ish noise', fill('AbC9+/=')],
  ['prefixes too short to be keys', fill('sk_live_abc!')],
  ['github_pat_ repeated', fill('github_pat_')],
  ['AKIA repeated', fill('AKIA')],
  ['xoxb- repeated', fill('xoxb-')],
]

for (const [name, text] of ADVERSARIAL) {
  test(`a megabyte of ${name} is scanned in well under a second`, () => {
    const started = Date.now()
    redact(text, 'all')
    expect(Date.now() - started).toBeLessThan(500)
  })
}
