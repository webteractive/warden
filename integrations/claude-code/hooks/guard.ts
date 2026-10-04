// The guard's pure half: which fields of a tool call can name a file, and
// reading warden's answer. The decision is warden's (`warden hook --guard
// --json`), and every guarded call is put to it as written: whether .e""nv,
// .ENV or `f=.env; cat $f` names an env file is a question about how the shell
// spells things, and a check here that answered it differently would be a way
// around the guard. Nothing here decides allow or deny while warden can run.
//
// Pure: nothing here touches `$`.

// What a guarded call hands warden: the tool and the fields of it that matter.
export type Guarded = {
  tool: string
  input: Record<string, string>
}

// The field each path-taking tool names its file in.
const PATH_FIELDS: Readonly<Record<string, string>> = {
  LSP: 'filePath',
  Read: 'file_path',
  Edit: 'file_path',
  Write: 'file_path',
  NotebookEdit: 'notebook_path',
  Grep: 'path',
}

// Tools whose command runs in a shell and whose output reaches the model.
const SHELL_TOOLS = new Set(['Bash', 'Monitor'])

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined
}

// Picks the fields warden judges for `tool`, or undefined for a tool the guard
// has no opinion on. Tools are compared by name: the set registered differs per
// build (the native macOS build has no Grep), so no matcher can list them.
export function guarded(tool: string, e: Readonly<Record<string, unknown>>): Guarded | undefined {
  if (SHELL_TOOLS.has(tool)) {
    const command = str(e.command)
    return command === undefined ? undefined : { tool, input: { command } }
  }
  const pathField = PATH_FIELDS[tool]
  if (pathField === undefined) return undefined
  const input: Record<string, string> = {}
  const path = str(e[pathField])
  if (path !== undefined) input[pathField] = path
  const glob = tool === 'Grep' ? str(e.glob) : undefined
  if (glob !== undefined) input.glob = glob
  if (Object.keys(input).length === 0) return undefined
  return { tool, input }
}

// Whether a call might spell an env file, for use only while warden cannot be
// run. Deliberately broad — any env or secrets in any case, ANSI-C quoting, and
// a dotfile word carrying a wildcard, brace, quote or backslash — because the
// alternative to holding a call here is letting it through unjudged. A name
// computed at run time still passes; so it does with warden, too.
const MIGHT_NAME = [
  /env|secrets/i,
  /\$'/,
  /(^|[\s/'"=@<(])[.[?][^\s/]*[*?[{"'\\]/,
]

export function mightNameEnvFile(texts: readonly (string | undefined)[]): boolean {
  return texts.some(t => t !== undefined && MIGHT_NAME.some(re => re.test(t)))
}

// The payload `warden hook --guard` reads on stdin.
export function payload(g: Guarded): string {
  return JSON.stringify({ tool_name: g.tool, tool_input: g.input })
}

export type GuardAnswer = {
  decision: 'allow' | 'deny'
  target?: 'env' | 'secrets'
  reason?: string
}

// Reads `warden hook --guard --json`. Undefined means the answer cannot be
// trusted either way — a binary too old for --json, a crash — and the caller
// treats that as warden being unavailable rather than as an allow.
export function parseGuardAnswer(exitCode: number, stdout: string): GuardAnswer | undefined {
  let answer: unknown
  try {
    answer = JSON.parse(stdout)
  } catch {
    return undefined
  }
  if (typeof answer !== 'object' || answer === null) return undefined
  const a = answer as Record<string, unknown>
  if (exitCode === 0 && a.decision === 'allow') return { decision: 'allow' }
  if (exitCode === 2 && a.decision === 'deny' && typeof a.reason === 'string') {
    const target = a.target === 'secrets' ? 'secrets' : 'env'
    return { decision: 'deny', target, reason: a.reason }
  }
  return undefined
}

// The denial while warden cannot be run. Only calls that name an env file reach
// it: blocking those is narrow enough to live with, and allowing them would let
// a stale binary wave `cat ~/.secrets` through while the guard looked healthy.
export function degradedReason(why: string): string {
  return `Denied: this call names .env or .secrets, and warden is not runnable here (${why}), ` +
    'so it cannot be checked. The user can reinstall warden ' +
    '(curl -fsSL https://raw.githubusercontent.com/webteractive/warden/main/install.sh | sh), ' +
    'then run /env refresh. Until then, ask the user rather than reading the file.'
}

// The warden subcommands that change a store, after which the health band is
// out of date. Judged per segment, on the first word, as the guard judges.
export function isWardenWrite(command: string): boolean {
  for (const segment of command.split(/&&|\|\||;|\||\n/)) {
    const words = segment.trim().split(/\s+/)
    if (words[0]?.split('/').pop() !== 'warden') continue
    const verb = firstVerb(words)
    if (verb === 'set' || verb === 'unset' || verb === 'clear' || verb === 'init') return true
    if (verb === 'classify' && words.some(w => w === '--set' || w.startsWith('--set='))) return true
    if (verb === 'vault' && words.includes('push')) return true
  }
  return false
}

// The subcommand: the first word after `warden` that is not a flag or the
// value of one. --project is the only global flag that takes a value.
function firstVerb(words: readonly string[]): string | undefined {
  for (let i = 1; i < words.length; i++) {
    const w = words[i] ?? ''
    if (w === '--project') {
      i++
      continue
    }
    if (!w.startsWith('-')) return w
  }
  return undefined
}
