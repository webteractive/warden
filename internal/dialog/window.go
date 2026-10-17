//go:build cgo || windows

package dialog

import (
	"errors"
	"os"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/io/system"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// errNoWindow means the platform gave no window to draw in.
var errNoWindow = errors.New("no window")

// Available reports whether this build can open the dialog window.
const Available = true

// Main runs the dialog child and exits; it never returns. The key and path come
// from the environment, never argv, so neither is parsed as a flag.
func Main() {
	key, path := os.Getenv(EnvKey), os.Getenv(EnvPath)
	if key == "" || path == "" {
		os.Exit(ExitUnavailable)
	}
	go func() {
		d, err := run(key, path)
		switch {
		case err != nil:
			os.Exit(ExitUnavailable)
		case d.Outcome() == Saved:
			// The one place the value leaves the dialog: down the pipe to the
			// warden that started this process.
			if _, err := os.Stdout.WriteString(d.Value().Expose()); err != nil {
				os.Exit(ExitUnavailable)
			}
			os.Exit(ExitSaved)
		default:
			os.Exit(ExitCancelled)
		}
	}()
	app.Main()
}

func run(key, path string) (*Dialog, error) {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(gofont.Collection()))
	d := New(th, key, path)

	w := new(app.Window)
	w.Option(
		app.Title("warden — "+key),
		app.Size(unit.Dp(560), unit.Dp(340)),
		app.MinSize(unit.Dp(420), unit.Dp(260)),
	)
	var ops op.Ops
	drew := false
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			if !drew && e.Err != nil {
				return nil, errNoWindow
			}
			d.Cancel()
			return d, nil
		case app.FrameEvent:
			drew = true
			gtx := app.NewContext(&ops, e)
			d.Layout(gtx)
			e.Frame(gtx.Ops)
			if d.Outcome() != Pending {
				w.Perform(system.ActionClose)
			}
		default:
			guardView(e)
		}
	}
}
