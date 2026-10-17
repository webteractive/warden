package dialog

// The dialog runs in a child warden process, started as
//
//	warden __warden-dialog
//
// with the key and path in its environment. A window needs the process's main
// thread on some platforms, and warden's own main thread belongs to the CLI, so
// the window gets a process of its own: the same executable, so there is no
// second binary to find, trust or swap.
const (
	Arg     = "__warden-dialog"
	EnvKey  = "WARDEN_DIALOG_KEY"
	EnvPath = "WARDEN_DIALOG_PATH"
)

// How the child reports back. Saved writes the value to stdout and nothing
// else; the others write nothing at all.
const (
	ExitSaved       = 0
	ExitCancelled   = 3
	ExitUnavailable = 4
)
