package dialog

import (
	"image"
	"testing"
	"time"

	"gioui.org/font/gofont"
	"gioui.org/io/input"
	"gioui.org/io/key"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// harness drives a Dialog through Gio's real input router with no window:
// events go in through Queue exactly as a platform driver would send them.
type harness struct {
	t   *testing.T
	r   *input.Router
	ops op.Ops
	d   *Dialog
	now time.Time
}

func newHarness(t *testing.T) *harness {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(gofont.Collection()))
	h := &harness{t: t, r: new(input.Router), d: New(th, "API_TOKEN", "/tmp/project/.env"), now: time.Unix(0, 0)}
	h.frame() // takes focus
	h.frame()
	return h
}

func (h *harness) frame() {
	h.ops.Reset()
	h.now = h.now.Add(time.Second)
	gtx := layout.Context{
		Ops:         &h.ops,
		Now:         h.now,
		Metric:      unitMetric,
		Constraints: layout.Exact(image.Pt(520, 320)),
		Source:      h.r.Source(),
	}
	h.d.Layout(gtx)
	h.r.Frame(&h.ops)
}

// do queues events, then runs the two frames Gio needs to deliver them and
// apply what they caused.
func (h *harness) do(events ...interface{ ImplementsEvent() }) {
	h.t.Helper()
	for _, e := range events {
		h.r.Queue(e)
	}
	h.frame()
	h.frame()
}

// typeText inserts s at the caret and moves the caret past it, as a platform's
// text input does: an EditEvent, then the SelectionEvent that follows it.
func (h *harness) typeText(s string) {
	h.t.Helper()
	at, _ := h.d.editor.Selection()
	end := at + len([]rune(s))
	h.do(
		key.EditEvent{Range: key.Range{Start: at, End: at}, Text: s},
		key.SelectionEvent{Start: end, End: end},
	)
}

func (h *harness) press(name key.Name, mods key.Modifiers) {
	h.t.Helper()
	h.do(key.Event{Name: name, Modifiers: mods, State: key.Press})
}

func (h *harness) click(c interface{ Click() }) {
	h.t.Helper()
	c.Click()
	h.frame()
	h.frame()
}

func TestStartsMaskedAndFocused(t *testing.T) {
	h := newHarness(t)
	if h.d.Revealed() {
		t.Fatal("the value must start hidden")
	}
	if h.d.editor.Mask != maskRune {
		t.Errorf("Mask = %q, want %q", h.d.editor.Mask, maskRune)
	}
	if h.d.editor.InputHint != key.HintPassword {
		t.Error("hidden, the field must hint a password to the input method")
	}
	h.typeText("hunter2")
	if got := h.d.editor.Text(); got != "hunter2" {
		t.Errorf("typing without clicking the field first should land in it; got %q", got)
	}
}

func TestRevealAndHideKeepTheText(t *testing.T) {
	h := newHarness(t)
	h.typeText("sk_live_abc")
	h.click(&h.d.reveal)
	if !h.d.Revealed() || h.d.editor.Mask != 0 {
		t.Fatal("Reveal must show the value in the clear")
	}
	h.typeText("def")
	h.click(&h.d.reveal)
	if h.d.Revealed() || h.d.editor.Mask != maskRune {
		t.Fatal("Hide must mask the value again")
	}
	if got := h.d.editor.Text(); got != "sk_live_abcdef" {
		t.Errorf("text after Reveal/Hide = %q", got)
	}
}

func TestSaveReturnsTheValueWithoutTrailingBreaks(t *testing.T) {
	h := newHarness(t)
	h.typeText("-----BEGIN-----\nabc\n-----END-----\n\n")
	h.click(&h.d.save)
	if h.d.Outcome() != Saved {
		t.Fatalf("Outcome = %v, want Saved", h.d.Outcome())
	}
	if got := h.d.Value().Expose(); got != "-----BEGIN-----\nabc\n-----END-----" {
		t.Errorf("Value = %q", got)
	}
}

func TestLongTokenFitsAndSurvives(t *testing.T) {
	h := newHarness(t)
	long := ""
	for len(long) < 4096 {
		long += "eyJhbGciOiJIUzI1NiJ9."
	}
	h.typeText(long)
	h.click(&h.d.save)
	if got := h.d.Value().Expose(); got != long {
		t.Errorf("a %d-byte token came back as %d bytes", len(long), len(got))
	}
}

func TestEmptySaveIsIgnored(t *testing.T) {
	h := newHarness(t)
	h.typeText("\n\n")
	h.click(&h.d.save)
	if h.d.Outcome() != Pending {
		t.Errorf("Save with only line breaks must not answer; Outcome = %v", h.d.Outcome())
	}
}

func TestReturnIsANewlineAndShortcutReturnSaves(t *testing.T) {
	h := newHarness(t)
	h.typeText("line1")
	h.press(key.NameReturn, 0)
	h.typeText("line2")
	if h.d.Outcome() != Pending {
		t.Fatal("a plain Return must not save a multi-line field")
	}
	h.press(key.NameReturn, key.ModShortcut)
	if h.d.Outcome() != Saved {
		t.Fatalf("Ctrl/Cmd+Return must save; Outcome = %v", h.d.Outcome())
	}
	if got := h.d.Value().Expose(); got != "line1\nline2" {
		t.Errorf("Value = %q", got)
	}
}

func TestEscapeCancels(t *testing.T) {
	h := newHarness(t)
	h.typeText("hunter2")
	h.press(key.NameEscape, 0)
	if h.d.Outcome() != Cancelled {
		t.Fatalf("Outcome = %v, want Cancelled", h.d.Outcome())
	}
	if h.d.Value() != "" {
		t.Error("a cancelled dialog must give no value")
	}
}

func TestCancelButtonCancels(t *testing.T) {
	h := newHarness(t)
	h.typeText("hunter2")
	h.click(&h.d.cancel)
	if h.d.Outcome() != Cancelled || h.d.Value() != "" {
		t.Fatalf("Outcome = %v", h.d.Outcome())
	}
}

func TestAnswerStands(t *testing.T) {
	h := newHarness(t)
	h.typeText("hunter2")
	h.click(&h.d.save)
	h.d.Cancel() // the window closing after Save
	if h.d.Outcome() != Saved {
		t.Error("closing the window after Save must not undo it")
	}
}

func TestHiddenValueCannotBeCopied(t *testing.T) {
	h := newHarness(t)
	h.typeText("hunter2")
	h.press("A", key.ModShortcut)
	h.press("C", key.ModShortcut)
	h.press("X", key.ModShortcut)
	if _, data, ok := h.r.WriteClipboard(); ok {
		t.Fatalf("a hidden value reached the clipboard (%d bytes)", len(data))
	}
	if got := h.d.editor.Text(); got != "hunter2" {
		t.Errorf("cut while hidden changed the value to %q", got)
	}

	// Revealed, it is the user's own text in the clear, and copies like any.
	h.click(&h.d.reveal)
	h.press("A", key.ModShortcut)
	h.press("C", key.ModShortcut)
	if _, data, ok := h.r.WriteClipboard(); !ok || string(data) != "hunter2" {
		t.Errorf("revealed copy: ok=%v", ok)
	}
}

var unitMetric = unit.Metric{PxPerDp: 1, PxPerSp: 1}
