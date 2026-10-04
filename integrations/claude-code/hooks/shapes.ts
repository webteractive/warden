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

type Rule = {
  rule: string
  label: string
  re: RegExp
  // What to call a match, or undefined when it is a placeholder, not a value.
  judge: (match: RegExpExecArray) => Confidence | undefined
  // The part of the match to replace; the whole match when absent.
  secret?: (match: RegExpExecArray) => { start: number; end: number }
}

// Every prefix warden's rules.go recognises, with the body that follows it.
const PREFIXES: ReadonlyArray<{ prefix: string; body: string; rule: string; label: string; confidence: Confidence }> = [
  { prefix: 'sk_live_', body: '[A-Za-z0-9]{16,}', rule: 'shape:stripe-live', label: 'a Stripe live key', confidence: 'live' },
  { prefix: 'rk_live_', body: '[A-Za-z0-9]{16,}', rule: 'shape:stripe-restricted', label: 'a Stripe restricted key', confidence: 'live' },
  { prefix: 'sk_test_', body: '[A-Za-z0-9]{16,}', rule: 'shape:stripe-test', label: 'a Stripe test key', confidence: 'test' },
  { prefix: 'github_pat_', body: '[A-Za-z0-9_]{22,}', rule: 'shape:github-pat', label: 'a GitHub token', confidence: 'live' },
  { prefix: 'ghp_', body: '[A-Za-z0-9]{36}\\b', rule: 'shape:github-pat', label: 'a GitHub token', confidence: 'live' },
  { prefix: 'gho_', body: '[A-Za-z0-9]{36}\\b', rule: 'shape:github-oauth', label: 'a GitHub OAuth token', confidence: 'live' },
  { prefix: 'ghs_', body: '[A-Za-z0-9]{36}\\b', rule: 'shape:github-server', label: 'a GitHub server token', confidence: 'live' },
  { prefix: 'xoxb-', body: '[A-Za-z0-9-]{10,}', rule: 'shape:slack-bot', label: 'a Slack bot token', confidence: 'live' },
  { prefix: 'xoxp-', body: '[A-Za-z0-9-]{10,}', rule: 'shape:slack-user', label: 'a Slack user token', confidence: 'live' },
  { prefix: 'xapp-', body: '[A-Za-z0-9-]{10,}', rule: 'shape:slack-app', label: 'a Slack app token', confidence: 'live' },
  { prefix: 'AKIA', body: '[A-Z0-9]{16}\\b', rule: 'shape:aws-access-key', label: 'an AWS access key', confidence: 'live' },
  { prefix: 'ASIA', body: '[A-Z0-9]{16}\\b', rule: 'shape:aws-temp-key', label: 'an AWS temporary key', confidence: 'live' },
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

const RULES: readonly Rule[] = [
  // Private keys only. warden's `-----BEGIN` is right for an env value, but in
  // tool output `openssl x509` and `curl -v` print public certificates all day.
  // An escaped block (`\n` written out, as dotenv stores one) is matched too,
  // and one cut off before its END line is taken to the end of its body.
  {
    rule: 'shape:pem-block',
    label: 'a private key',
    re: /-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----(?:[\s\S]*?-----END \1PRIVATE KEY-----|[A-Za-z0-9+/=\s\\]*)/g,
    judge: () => 'live',
  },
  ...PREFIXES.map(({ prefix, body, rule, label, confidence }) => ({
    rule,
    label,
    re: new RegExp(`(?<![A-Za-z0-9_])${escape(prefix)}${body}`, 'g'),
    judge: () => confidence,
  })),
  {
    rule: 'shape:jwt',
    label: 'a JWT',
    // `eyJ` is warden's prefix: base64 of `{"`. Three dotted parts make it a token.
    re: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    judge: () => 'test',
  },
  {
    rule: 'shape:url-userinfo',
    label: 'a URL with a password in it',
    re: /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s/@:]+:([^\s/@]+)@([^\s/:?#]+)/g,
    judge: m => {
      const password = m[1] ?? ''
      if (isPlaceholder(password)) return undefined
      return LOCAL_HOSTS.has((m[2] ?? '').toLowerCase()) ? 'test' : 'live'
    },
    // Only the password goes; the scheme, user and host are what make the
    // output useful, and they are not the secret.
    secret: m => {
      const password = m[1] ?? ''
      const start = m.index + m[0].lastIndexOf(`:${password}@`) + 1
      return { start, end: start + password.length }
    },
  },
]

// Output past this is not scanned: the same cap $.process.run applies.
const SCAN_LIMIT = 4 * 1024 * 1024

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
  let head = text.length > SCAN_LIMIT ? text.slice(0, SCAN_LIMIT) : text
  const tail = text.length > SCAN_LIMIT ? text.slice(SCAN_LIMIT) : ''

  for (const rule of RULES) {
    rule.re.lastIndex = 0
    let out = ''
    let last = 0
    for (let m = rule.re.exec(head); m !== null; m = rule.re.exec(head)) {
      const confidence = rule.judge(m)
      if (confidence === undefined) continue
      const finding = { rule: rule.rule, label: rule.label, confidence }
      findings.push(finding)
      if (!shouldRedact(level, confidence)) continue
      redacted.push(finding)
      const span = rule.secret?.(m) ?? { start: m.index, end: m.index + m[0].length }
      out += head.slice(last, span.start) + marker(rule.rule)
      last = span.end
    }
    head = out + head.slice(last)
  }
  return { text: head + tail, findings, redacted }
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
