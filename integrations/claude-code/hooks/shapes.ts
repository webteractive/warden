// Credential shapes in free text: the tripwire's half of warden's value-shape
// rules (internal/classify/rules.go).
//
// warden checks a whole env value with an anchored prefix. Tool output is free
// text, so each rule here is the same prefix, unanchored, followed by enough of
// a body to be a credential rather than a mention of one. Rule names are
// warden's own, so `warden classify` and this file call a thing the same name.
// Every prefix in rules.go must appear in PREFIXES below; a Go test
// (internal/classify/mod_parity_test.go) fails when one does not.
//
// Pure: nothing here touches `$`. The engine follows `$` only within
// register.tsx.

export type Confidence = 'live' | 'test'

export type Redaction = 'live' | 'all' | 'off'

export type Finding = { rule: string; label: string; confidence: Confidence }

// One place a rule matched: the part to replace and what to call it.
type Span = { start: number; end: number; confidence: Confidence }

// Every rule finds its spans in one pass over the text, in order and without
// overlap. Each must be linear in the text's length: a tool result can be
// megabytes, and a scan that backtracks stalls the session it runs in.
type Rule = {
  rule: string
  label: string
  find: (text: string) => Span[]
}

// A rule from a global regex. `judge` names a match, or rejects it as a
// placeholder; `secret` picks the part to replace, the whole match by default.
function byRegex(
  re: RegExp,
  judge: (m: RegExpExecArray) => Confidence | undefined,
  secret?: (m: RegExpExecArray) => { start: number; end: number },
): (text: string) => Span[] {
  return text => {
    const spans: Span[] = []
    re.lastIndex = 0
    for (let m = re.exec(text); m !== null; m = re.exec(text)) {
      const confidence = judge(m)
      if (confidence === undefined) continue
      spans.push({ ...(secret?.(m) ?? { start: m.index, end: m.index + m[0].length }), confidence })
    }
    return spans
  }
}

// Every prefix warden's rules.go recognises, with the body that follows it.
const PREFIXES: ReadonlyArray<{ prefix: string; body: string; rule: string; label: string; confidence: Confidence }> = [
  { prefix: 'sk_live_', body: '[A-Za-z0-9]{16,}', rule: 'shape:stripe-live', label: 'a Stripe live key', confidence: 'live' },
  { prefix: 'rk_live_', body: '[A-Za-z0-9]{16,}', rule: 'shape:stripe-restricted', label: 'a Stripe restricted key', confidence: 'live' },
  { prefix: 'sk_test_', body: '[A-Za-z0-9]{16,}', rule: 'shape:stripe-test', label: 'a Stripe test key', confidence: 'test' },
  { prefix: 'github_pat_', body: '[A-Za-z0-9_]{22,}', rule: 'shape:github-pat', label: 'a GitHub token', confidence: 'live' },
  { prefix: 'ghp_', body: '[A-Za-z0-9]{36}(?![A-Za-z0-9])', rule: 'shape:github-pat', label: 'a GitHub token', confidence: 'live' },
  { prefix: 'gho_', body: '[A-Za-z0-9]{36}(?![A-Za-z0-9])', rule: 'shape:github-oauth', label: 'a GitHub OAuth token', confidence: 'live' },
  { prefix: 'ghs_', body: '[A-Za-z0-9]{36}(?![A-Za-z0-9])', rule: 'shape:github-server', label: 'a GitHub server token', confidence: 'live' },
  { prefix: 'xoxb-', body: '[A-Za-z0-9-]{10,}', rule: 'shape:slack-bot', label: 'a Slack bot token', confidence: 'live' },
  { prefix: 'xoxp-', body: '[A-Za-z0-9-]{10,}', rule: 'shape:slack-user', label: 'a Slack user token', confidence: 'live' },
  { prefix: 'xapp-', body: '[A-Za-z0-9-]{10,}', rule: 'shape:slack-app', label: 'a Slack app token', confidence: 'live' },
  { prefix: 'AKIA', body: '[A-Z0-9]{16}(?![A-Z0-9])', rule: 'shape:aws-access-key', label: 'an AWS access key', confidence: 'live' },
  { prefix: 'ASIA', body: '[A-Z0-9]{16}(?![A-Z0-9])', rule: 'shape:aws-temp-key', label: 'an AWS temporary key', confidence: 'live' },
]

// Passwords that every .env.example and README carries; a URL with one of these
// in it is documentation, not a leak.
const PLACEHOLDERS = new Set([
  'password', 'pass', 'passwd', 'secret', 'changeme', 'xxx', 'xxxx', 'xxxxxx', '***', '****',
  'pw', 'pwd', 'example', 'your_password', 'yourpassword', 'mypassword',
])

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '[::1]', 'host.docker.internal'])

function isPlaceholder(password: string): boolean {
  const lower = password.toLowerCase()
  return PLACEHOLDERS.has(lower) ||
    /^[*x]+$/i.test(password) ||
    /^<.*>$/.test(password) ||
    /^\$\{.*\}$/.test(password) ||
    /^\{\{.*\}\}$/.test(password) ||
    password === '%s'
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// A PEM label is short; bounding it keeps a run of capitals after BEGIN from
// being retried at every length.
const PEM_BEGIN = /-----BEGIN ([A-Z0-9 ]{0,40})PRIVATE KEY( BLOCK)?-----/g
const PEM_END = /-----END ([A-Z0-9 ]{0,40})PRIVATE KEY( BLOCK)?-----/g
// What a key's body can hold, including an encrypted key's Proc-Type and
// DEK-Info headers and the written-out \n of an escaped block.
const PEM_BODY = /[A-Za-z0-9+/=\s\\:,.-]*/y
// An END this far past its BEGIN belongs to something else; a PGP key with
// subkeys is a few kilobytes.
const PEM_REACH = 64 * 1024

// Private keys, found without a backtracking search for END: every END marker
// is indexed once, and each BEGIN takes the next END with its label. A key cut
// off before its END is taken to the end of its body.
function pemSpans(text: string): Span[] {
  const ends = new Map<string, number[]>()
  for (const m of text.matchAll(PEM_END)) {
    const label = `${m[1] ?? ''}|${m[2] ?? ''}`
    const list = ends.get(label)
    if (list === undefined) ends.set(label, [m.index + m[0].length])
    else list.push(m.index + m[0].length)
  }
  const cursors = new Map<string, number>()
  const spans: Span[] = []
  let last = 0
  for (const m of text.matchAll(PEM_BEGIN)) {
    if (m.index < last) continue
    const label = `${m[1] ?? ''}|${m[2] ?? ''}`
    const list = ends.get(label) ?? []
    let i = cursors.get(label) ?? 0
    while (i < list.length && (list[i] ?? 0) <= m.index) i++
    cursors.set(label, i)
    const end = list[i]
    let stop: number
    if (end !== undefined && end - m.index <= PEM_REACH) {
      stop = end
    } else {
      PEM_BODY.lastIndex = m.index + m[0].length
      PEM_BODY.exec(text)
      stop = PEM_BODY.lastIndex
    }
    spans.push({ start: m.index, end: stop, confidence: 'live' })
    last = stop
  }
  return spans
}

const RULES: readonly Rule[] = [
  // Private keys only. warden's `-----BEGIN` is right for an env value, but in
  // tool output `openssl x509` and `curl -v` print public certificates all day.
  // PGP's PRIVATE KEY BLOCK counts.
  { rule: 'shape:pem-block', label: 'a private key', find: pemSpans },
  ...PREFIXES.map(({ prefix, body, rule, label, confidence }) => ({
    rule,
    label,
    // No boundary in front: a value follows `\n` in JSON-escaped output and
    // `%3D` in a URL, and both put a word character right before it. Each
    // prefix is distinctive enough to stand alone, and each body either
    // succeeds or stops at the first character it cannot take.
    find: byRegex(new RegExp(`${escape(prefix)}${body}`, 'g'), () => confidence),
  })),
  {
    rule: 'shape:jwt',
    label: 'a JWT',
    // `eyJ` is warden's prefix: base64 of `{"`. Three dotted parts make it a
    // token. It starts only where a token can, after a character outside the
    // alphabet or a JSON escape like \n: starting inside a run of eyJeyJeyJ
    // would rescan the run from every position, which is quadratic.
    find: byRegex(
      /(?:(?<![A-Za-z0-9_-])|(?<=\\[nrt]))eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
      () => 'test',
    ),
  },
  {
    rule: 'shape:url-userinfo',
    label: 'a URL with a password in it',
    // Every part is bounded, so a run of dotted words is not tried as a
    // scheme from each dot to the end. The password runs to the last @ before
    // the host, as URL parsers read it, so one containing a raw @ goes whole.
    find: byRegex(
      /\b[a-zA-Z][a-zA-Z0-9+.-]{0,31}:\/\/[^\s/@:]{1,256}:([^\s/]{1,512})@([^\s/:?#@]{1,253})/g,
      m => {
        const password = m[1] ?? ''
        if (isPlaceholder(password)) return undefined
        return LOCAL_HOSTS.has((m[2] ?? '').toLowerCase()) ? 'test' : 'live'
      },
      // Only the password goes; the scheme, user and host are what make the
      // output useful, and they are not the secret.
      m => {
        const password = m[1] ?? ''
        const start = m.index + m[0].lastIndexOf(`:${password}@`) + 1
        return { start, end: start + password.length }
      },
    ),
  },
]

export function marker(rule: string): string {
  return `[warden: redacted ${rule}]`
}

function shouldRedact(level: Redaction, confidence: Confidence): boolean {
  return level === 'all' || (level === 'live' && confidence === 'live')
}

export type Scanned = { text: string; findings: Finding[]; redacted: Finding[] }

// Finds every credential shape in `text` and removes the ones `level` covers.
// Rules run in order on the text as earlier rules left it, so a private key is
// gone before the shorter rules look inside it.
export function redact(text: string, level: Redaction): Scanned {
  const findings: Finding[] = []
  const redacted: Finding[] = []
  if (text.length === 0) return { text, findings, redacted }
  // All of it: a value past any cap would pass through unredacted.
  let head = text

  for (const rule of RULES) {
    let out = ''
    let last = 0
    for (const span of rule.find(head)) {
      const finding = { rule: rule.rule, label: rule.label, confidence: span.confidence }
      findings.push(finding)
      if (!shouldRedact(level, span.confidence)) continue
      redacted.push(finding)
      out += head.slice(last, span.start) + marker(rule.rule)
      last = span.end
    }
    head = out + head.slice(last)
  }
  return { text: head, findings, redacted }
}

function distinct(findings: readonly Finding[]): Finding[] {
  const seen = new Map<string, Finding>()
  for (const f of findings) if (!seen.has(f.rule)) seen.set(f.rule, f)
  return [...seen.values()]
}

function count(findings: readonly Finding[], rule: string): number {
  return findings.filter(f => f.rule === rule).length
}

// What the model reads after the output. Rule names and counts only — never a
// value, part of one, or anything derived from one.
export function modelNote(findings: readonly Finding[], redacted: readonly Finding[]): string | undefined {
  if (findings.length === 0) return undefined
  const lines: string[] = []
  if (redacted.length > 0) {
    const rules = distinct(redacted).map(f => `${count(redacted, f.rule)} shaped like ${f.rule}`).join(', ')
    lines.push(
      `warden: ${redacted.length === 1 ? 'a value' : `${redacted.length} values`} (${rules}) ` +
      'was removed from this output before you saw it. You do not hold it — do not run anything ' +
      'to see it again, and do not use warden set --exposed for it. Tell the user it was printed ' +
      'and should be rotated at the provider; the replacement goes in with ' +
      'warden set --secret KEY (or --from-file PATH).',
    )
  }
  const kept = findings.filter(f => !redacted.includes(f))
  if (kept.length > 0) {
    const rules = distinct(kept).map(f => f.rule).join(', ')
    lines.push(
      `warden: this output contains ${kept.length === 1 ? 'a value' : `${kept.length} values`} ` +
      `shaped like ${rules}. You now hold ${kept.length === 1 ? 'it' : 'them'}: never repeat ` +
      `${kept.length === 1 ? 'it' : 'them'} in a reply, file or commit. If one belongs in an env ` +
      'file, warden set --exposed KEY VALUE is the honest channel, since you already have it; ' +
      'if it is a live credential, tell the user to rotate it.',
    )
  }
  return lines.join('\n')
}

// What the person sees, as a toast and a transcript notice.
export function personNote(tool: string, findings: readonly Finding[], redacted: readonly Finding[]): string {
  const first = distinct(redacted)[0] ?? distinct(findings)[0]
  const others = distinct(findings).length - 1
  const more = others > 0 ? ` (and ${others} other kind${others > 1 ? 's' : ''})` : ''
  const what = `${first?.label ?? 'a credential'}${more} appeared in ${tool} output`
  if (redacted.length > 0) {
    return `warden: ${what} — redacted for the model. Rotate it; it is still in scrollback and the transcript file.`
  }
  return `warden: ${what}. The model has seen it; rotate it if it is live.`
}
