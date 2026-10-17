//go:build !cgo && !windows

package dialog

import "os"

// Available reports whether this build can open the dialog window. Gio needs
// cgo for a window on Linux and macOS, and release builds are CGO_ENABLED=0,
// so those builds keep the channels they had.
const Available = false

// Main exits as unavailable: this build has no window to show.
func Main() { os.Exit(ExitUnavailable) }
