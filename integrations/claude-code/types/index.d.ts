// The warden mod's state contract: every value it keeps in $.state. None holds
// a value from an env file — only key names, classes, counts and warden's own
// value-free messages.

export type Severity = 'info' | 'warn' | 'error'

export type Scope = 'project' | 'global'

// One `warden doctor --json` finding.
export type Problem = {
  code: string
  key?: string
  severity: Severity
  message: string
  fix?: string
}

export type Shown = Problem & { scope: Scope }

export type Health = {
  // null: no file in that scope (or the check failed; see error).
  project: Problem[] | null
  global: Problem[] | null
  // The project has .env.example but no .env.
  noEnvButExample: boolean
  checkedAt: number
  error?: string
}

export type GuardStatus = {
  mode: 'unknown' | 'warden' | 'degraded'
  binary?: string
  version?: string
  reason?: string
  // Whether warden's own dialog can be shown: macOS only.
  canPrompt: boolean
  denies: { env: number; secrets: number }
}

export type LeakTally = {
  total: number
  redacted: number
  byRule: Record<string, number>
}

export type EnvRow = {
  key: string
  class: 'secret' | 'public'
  set: boolean
  flags: string[]
}

export type PaneAction = 'set' | 'generate'

export type PaneState = {
  scope: Scope
  rows: EnvRow[] | null
  selected: string | null
  pending: { key: string; action: PaneAction } | null
  why: { key: string; rule: string } | null
  error?: string
}

declare module 'claude-code' {
  interface PluginState {
    warden: {
      guard: GuardStatus
      leaks: LeakTally
      health: Health | null
      bandHiddenFor: string | null
      pane: PaneState
    }
  }
}
