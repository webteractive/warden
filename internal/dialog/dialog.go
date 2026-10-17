// Package dialog is warden's own window for collecting a secret value: a
// multi-line field, masked until the user presses Reveal, that runs wherever
// Gio has a window driver rather than only where osascript exists.
//
// The widget here is pure Gio layout with no window behind it, so every
// behaviour (typing, Reveal, Save, Cancel, the copy block) is driven headlessly
// by the tests on any platform. window.go puts it in a real window.
//
// The typed value never leaves this package except through Value, and never
// appears in an error.
package dialog

import (
	"image"
	"image/color"
	"strings"

	"gioui.org/font"
	"gioui.org/io/event"
	"gioui.org/io/key"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/webteractive/warden/internal/secret"
)

// Outcome is where the dialog stands.
type Outcome int

const (
	// Pending means the user has not answered yet.
	Pending Outcome = iota
	// Saved means the user pressed Save with a non-empty value.
	Saved
	// Cancelled means the user pressed Cancel or Escape, or closed the window.
	Cancelled
)

// maskRune is what each character shows as while the value is hidden.
const maskRune = '•'

// Dialog asks for one key's value.
type Dialog struct {
	Key, Path string

	theme    *material.Theme
	editor   widget.Editor
	reveal   widget.Clickable
	save     widget.Clickable
	cancel   widget.Clickable
	revealed bool
	outcome  Outcome
	focused  bool
}

// New returns a dialog for key, naming path so the user can see which file
// they are authorising a write to.
func New(th *material.Theme, key, path string) *Dialog {
	d := &Dialog{Key: key, Path: path, theme: th}
	d.setRevealed(false)
	return d
}

// Revealed reports whether the value is shown in the clear.
func (d *Dialog) Revealed() bool { return d.revealed }

// Outcome reports whether the user has answered, and how.
func (d *Dialog) Outcome() Outcome { return d.outcome }

// Cancel answers the dialog as cancelled, as closing its window does. An answer
// already given stands.
func (d *Dialog) Cancel() {
	if d.outcome == Pending {
		d.outcome = Cancelled
	}
}

// Value returns what was typed once the dialog is Saved, and "" otherwise.
//
// Trailing line breaks are dropped: a token pasted into a multi-line field
// often brings one along, or the Return a user pressed out of habit. Line
// breaks inside the value, as in a PEM block, are kept.
func (d *Dialog) Value() secret.Secret {
	if d.outcome != Saved {
		return ""
	}
	return secret.Secret(trimValue(d.editor.Text()))
}

func trimValue(s string) string { return strings.TrimRight(s, "\r\n") }

// setRevealed switches between the masked and clear views. Hidden, the field
// also hints a password to the platform's input method, which on Wayland keeps
// an IME from learning the value.
func (d *Dialog) setRevealed(on bool) {
	d.revealed = on
	if on {
		d.editor.Mask = 0
		d.editor.InputHint = key.HintAny
	} else {
		d.editor.Mask = maskRune
		d.editor.InputHint = key.HintPassword
	}
}

// update handles everything the user did since the last frame. It runs before
// the editor lays out, so the copy block below sees shortcuts first.
func (d *Dialog) update(gtx layout.Context) {
	if !d.focused {
		gtx.Execute(key.FocusCmd{Tag: &d.editor})
		d.focused = true
	}
	if d.reveal.Clicked(gtx) {
		d.setRevealed(!d.revealed)
		gtx.Execute(key.FocusCmd{Tag: &d.editor})
	}
	if d.cancel.Clicked(gtx) {
		d.Cancel()
	}
	if d.save.Clicked(gtx) {
		d.trySave()
	}

	for {
		ev, ok := gtx.Event(
			// Escape cancels and Ctrl/Cmd+Return saves wherever focus is; a plain
			// Return is a newline, as in any multi-line field.
			key.Filter{Name: key.NameEscape},
			key.Filter{Name: key.NameReturn, Required: key.ModShortcut},
			key.Filter{Name: key.NameEnter, Required: key.ModShortcut},
		)
		if !ok {
			break
		}
		if e, ok := ev.(key.Event); ok && e.State == key.Press {
			if e.Name == key.NameEscape {
				d.Cancel()
			} else {
				d.trySave()
			}
		}
	}

	// Gio's editor copies its real text even while masked. Taking the copy and
	// cut shortcuts here, before the editor reads its own events, means a
	// hidden value never reaches the clipboard.
	if !d.revealed {
		for {
			if _, ok := gtx.Event(
				key.Filter{Focus: &d.editor, Name: "C", Required: key.ModShortcut},
				key.Filter{Focus: &d.editor, Name: "X", Required: key.ModShortcut},
			); !ok {
				break
			}
		}
	}
}

// trySave saves only a value with something in it: an empty one would be
// written as an empty key, which nobody pressing Save meant.
func (d *Dialog) trySave() {
	if d.outcome == Pending && trimValue(d.editor.Text()) != "" {
		d.outcome = Saved
	}
}

// Layout handles input and draws the dialog.
func (d *Dialog) Layout(gtx layout.Context) layout.Dimensions {
	d.update(gtx)
	th := d.theme
	paint.Fill(gtx.Ops, th.Palette.Bg)
	// The window's own event handler, so Escape and Ctrl/Cmd+Return reach the
	// dialog wherever focus is.
	defer clip.Rect{Max: gtx.Constraints.Max}.Push(gtx.Ops).Pop()
	event.Op(gtx.Ops, d)

	revealLabel := "Reveal"
	if d.revealed {
		revealLabel = "Hide"
	}
	return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.H6(th, "warden — "+d.Key)
				l.Font.Weight = font.Bold
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(material.Body2(th, "Enter the value for "+d.Key+". It will be written to:").Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Body2(th, d.Path)
				l.Font.Typeface = "Go Mono"
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Flexed(1, d.layoutField),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(d.secondary(&d.reveal, revealLabel)),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Dimensions{Size: image.Pt(gtx.Constraints.Min.X, 0)}
					}),
					layout.Rigid(d.secondary(&d.cancel, "Cancel")),
					layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
					layout.Rigid(material.Button(th, &d.save, "Save").Layout),
				)
			}),
		)
	})
}

func (d *Dialog) secondary(c *widget.Clickable, label string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		b := material.Button(d.theme, c, label)
		b.Background = color.NRGBA{R: 0xe8, G: 0xe8, B: 0xec, A: 0xff}
		b.Color = d.theme.Palette.Fg
		return b.Layout(gtx)
	}
}

// layoutField draws the bordered, wrapping text area.
func (d *Dialog) layoutField(gtx layout.Context) layout.Dimensions {
	border := widget.Border{
		Color:        color.NRGBA{R: 0x9a, G: 0x9a, B: 0xa6, A: 0xff},
		CornerRadius: unit.Dp(4),
		Width:        unit.Dp(1),
	}
	gtx.Constraints.Min = gtx.Constraints.Max
	return border.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			// The editor scrolls itself once the value outgrows the field.
			gtx.Constraints.Min = gtx.Constraints.Max
			e := material.Editor(d.theme, &d.editor, "Paste or type the value")
			e.Font.Typeface = "Go Mono"
			e.TextSize = unit.Sp(14)
			return e.Layout(gtx)
		})
	})
}
