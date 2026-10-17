//go:build !windows && cgo

package dialog

import "gioui.org/io/event"

// guardView does nothing here. X11 and Wayland have no way for a window to
// opt out of capture; macOS has one, and is still served by the osascript
// dialog until this window gains it along with secure keyboard input.
func guardView(event.Event) {}
