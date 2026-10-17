package dialog

import (
	"syscall"

	"gioui.org/app"
	"gioui.org/io/event"
)

var setWindowDisplayAffinity = syscall.NewLazyDLL("user32.dll").NewProc("SetWindowDisplayAffinity")

// wdaExcludeFromCapture keeps the window out of screenshots, recordings and
// screen sharing (Windows 10 2004 and later).
const wdaExcludeFromCapture = 0x11

// guardView keeps the dialog out of screen capture once its window exists.
func guardView(e event.Event) {
	if v, ok := e.(app.Win32ViewEvent); ok && v.HWND != 0 {
		setWindowDisplayAffinity.Call(v.HWND, wdaExcludeFromCapture)
	}
}
