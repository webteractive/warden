// Package write is the only path that modifies configuration.
//
// Public keys are written directly. Secret keys are written only through a
// prompt.Prompter, so the value arrives from the user rather than from the
// caller — which is what keeps an agent from ever handling it.
package write

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/webteractive/warden/internal/classify"
	"github.com/webteractive/warden/internal/exposure"
	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/query"
	"github.com/webteractive/warden/internal/secret"
	"github.com/webteractive/warden/internal/store"
)

// ErrSecretKey means the write was refused because the key, or the value
// offered for it, is sensitive.
var ErrSecretKey = errors.New("key is secret — use set --secret")

// ErrCredentialShape means the refusal came from the value rather than the key:
// an innocent key name is not permission to store a live API key in the clear.
//
// It accompanies ErrSecretKey rather than replacing it, so callers matching on
// the refusal keep working while a surface that wants to explain *which* of the
// two happened can ask. The distinction changes the advice: a secret key needs a
// different channel, whereas a public key holding a credential-shaped value
// usually means the key was misclassified.
var ErrCredentialShape = errors.New("the value looks like a credential")

// ErrUnwaivableShape means a key could not be made public because its value is a
// recognised credential format. Classify puts shape ahead of the schema, so the
// override would have been inert — this is a refusal rather than a silent no-op.
var ErrUnwaivableShape = errors.New(
	"cannot be made public: its value is a recognised credential format, " +
		"which outranks any override")

// ErrGlobalScope means a reclassification was attempted against ~/.secrets.
// That file holds secrets by definition, so an override there has no legitimate
// use and would only serve to unmask one.
var ErrGlobalScope = errors.New("reclassification is not available in global scope")

// ErrHasValue means a quiet reclassification was refused because the key
// already holds a value. Loosening one is exactly what the retype ceremony
// exists for, so that case is sent to `classify --set public` rather than given
// a second, weaker path.
var ErrHasValue = errors.New(
	"already holds a value — loosening a live secret needs the full ceremony")

// ErrRuleMatched means a quiet reclassification was refused because a rule, not
// the closing default, is what made the key secret. Overriding a rule is a
// claim that the rule is wrong, which is worth a deliberate command rather than
// a flag on the one that also supplies the value.
var ErrRuleMatched = errors.New(
	"is secret because a rule matched it, not because warden failed closed — " +
		"overriding a rule needs the full ceremony")

// ErrAbsent means the key does not appear in the file at all, so there is
// nothing to remove or empty. Distinct from a key that is present and empty:
// that one has a line to delete.
var ErrAbsent = errors.New("key is not present")

// W is an open, writable view of one store.
type W struct {
	st            store.Store
	userSchema    *classify.Schema
	projectSchema *classify.Schema
	p             prompt.Prompter
	global        bool
	home          string
	projectDir    string
}

// Open resolves the scope and attaches the prompter used for secret writes.
func Open(sc query.Scope, p prompt.Prompter) (*W, error) {
	w := &W{p: p, global: sc.Global, home: sc.Home}
	var err error
	if sc.Global {
		w.st, err = store.OpenSecrets(sc.Home)
	} else {
		w.st, err = store.OpenDotenv(sc.Dir)
	}
	if err != nil {
		return nil, err
	}
	if !sc.Global {
		resolvedProjectDir := filepath.Dir(w.st.Path())
		w.projectDir, err = classify.CanonicalProjectRoot(resolvedProjectDir)
		if err != nil {
			return nil, err
		}
		w.userSchema, err = classify.LoadUserSchema(sc.Home, w.projectDir)
		if err != nil {
			return nil, err
		}
		w.projectSchema, err = classify.LoadSchema(resolvedProjectDir)
		if err != nil {
			return nil, err
		}
	}
	return w, nil
}

// Path is the backing file.
func (w *W) Path() string { return w.st.Path() }

// SchemaPath is the central registry that holds project-scoped classification
// overrides. Reclassify refuses global scope before this path is used.
func (w *W) SchemaPath() string {
	return classify.UserSchemaPath(w.home)
}

// ProjectPath is the resolved project directory whose registry entry changes.
func (w *W) ProjectPath() string { return w.projectDir }

// SetPublic writes a value directly. It refuses if the key is secret, and also
// if the incoming value itself looks like a credential — an innocent key name
// is not permission to store a live API key in the clear.
func (w *W) SetPublic(key, value string) error {
	if w.classOf(key).Class == classify.Secret {
		return fmt.Errorf("%s: %w", key, ErrSecretKey)
	}
	if classify.Classify(key, secret.Secret(value), w.userSchema, w.projectSchema).Class == classify.Secret {
		return fmt.Errorf("%s: %w (%w)", key, ErrSecretKey, ErrCredentialShape)
	}
	if err := w.st.Set(key, value); err != nil {
		return err
	}
	return w.unmark(key)
}

// SetExposed writes a value the caller already holds, and records that it did.
//
// Every other write path exists to keep a secret away from the caller. This one
// accepts that the secret is already out — printed by a tool, pasted into a
// terminal, sitting in scrollback — and that making the user launder it through
// a prompt protects nothing it has not already lost.
//
// What it does not do is pretend otherwise. The value goes onto a command line,
// so it reaches shell history and argv, and that is durable in a way scrollback
// is not. The exposure is recorded so doctor keeps saying so until the key is
// rewritten through a channel that does not expose it.
//
// Classification is untouched: the key stays secret and warden get still
// refuses. This flag describes how the value got in, not who may read it. The
// credential-shape refusal is skipped for the same reason — a burned Stripe key
// is exactly what this is for, so refusing its shape would refuse the only case
// it serves.
//
// Overwriting a key that already holds a value is confirmed, because that
// destroys a credential rather than provisioning one. Every other destructive
// path asks — Unset and Clear both do — and this one reaches the same store
// through a flag that skips the prompt the secret channel would otherwise have
// imposed. Without this, `set --exposed` is the only way to silently replace a
// live secret.
func (w *W) SetExposed(key, value string) error {
	if w.has(key) {
		if err := w.p.ConfirmAction("expose", key, w.st.Path()); err != nil {
			return err
		}
	}
	if err := w.st.Set(key, value); err != nil {
		return err
	}
	return exposure.Record(w.home, w.exposureScope(), key)
}

// unmark clears a stale exposure record after a write through a channel that
// did not expose anything. The stored value is no longer the burned one, so the
// warning has to stop — a warning that cannot be cleared is one people learn to
// scroll past.
func (w *W) unmark(key string) error {
	return exposure.Clear(w.home, w.exposureScope(), key)
}

// exposureScope names the file the record is about. Project writes are recorded
// against the canonical project root, global ones against ~/.secrets itself,
// which has no project to belong to.
func (w *W) exposureScope() string {
	if w.global {
		return w.st.Path()
	}
	return w.projectDir
}

// SetSecret collects the value through the prompter and writes it. A cancelled
// prompt writes nothing.
//
// It also tightens the key's classification first, so that a value stored
// through the secret channel is not handed straight back by warden get. The
// order matters: tightening before the write means a failure here leaves
// nothing stored, while the reverse would leave a readable value behind.
func (w *W) SetSecret(key string) error {
	if err := w.tighten(key); err != nil {
		return err
	}
	v, err := w.p.AskSecret(key, w.st.Path())
	if err != nil {
		return err
	}
	if err := w.st.Set(key, v.Expose()); err != nil {
		return err
	}
	return w.unmark(key)
}

// tighten records a secret override for a key the classifier would otherwise
// call public, so choosing the secret channel actually means something.
//
// Without it, `warden set --secret VITE_ANALYTICS_ID` stores the value through
// the channel built to keep it away from the caller, and then `warden get`
// prints it — because VITE_* is on the public allowlist and nothing consulted
// the classifier on the way in.
//
// Unlike Reclassify, this does not ask. The user chose the secret channel by
// typing --secret; a dialog confirming the consequence of the flag they just
// passed is ceremony, and ceremony that fires when nothing is at stake is how
// people learn to dismiss the ceremony that matters.
//
// A no-op in global scope (~/.secrets is secret by definition, and there is no
// project to record an override against) and for the great majority of keys,
// which are already secret by the fail-closed default.
func (w *W) tighten(key string) error {
	if w.global || w.classOf(key).Class == classify.Secret {
		return nil
	}
	if _, err := classify.SetUserClass(w.home, w.projectDir, key, classify.Secret); err != nil {
		return err
	}
	sch, err := classify.LoadUserSchema(w.home, w.projectDir)
	if err != nil {
		return err
	}
	w.userSchema = sch
	return nil
}

// Unset removes every assignment of key and reports how many it removed.
//
// A key holding a value goes through the prompt first. Nothing is revealed by a
// deletion, so the risk being guarded is destruction, not disclosure — the user
// may not be able to recover the value from anywhere else. A key that is absent
// or already empty skips the prompt: there is nothing to lose, and asking anyway
// would train the answer.
func (w *W) Unset(key string) (int, error) {
	v, present := w.st.Get(key)
	if !present {
		return 0, fmt.Errorf("%s: %w", key, ErrAbsent)
	}
	if v.IsSet() {
		if err := w.p.ConfirmAction("remove", key, w.st.Path()); err != nil {
			return 0, err
		}
	}
	n, err := w.st.Unset(key)
	if err != nil {
		return n, err
	}
	// Deleting the key is the most complete remediation available for a burned
	// credential, so it has to clear the warning too. Leaving the record behind
	// leaves doctor reporting a key that no longer exists, with no way to
	// silence it — and --strict then fails on a problem that has been fixed.
	return n, w.unmark(key)
}

// Clear empties a key's value while leaving it declared, so it still shows up in
// warden list as declared-but-unset. Same authorisation rule as Unset.
func (w *W) Clear(key string) error {
	v, present := w.st.Get(key)
	if !present {
		return fmt.Errorf("%s: %w", key, ErrAbsent)
	}
	if !v.IsSet() {
		return nil
	}
	if err := w.p.ConfirmAction("clear", key, w.st.Path()); err != nil {
		return err
	}
	if err := w.st.Set(key, ""); err != nil {
		return err
	}
	// Emptying the key discards the burned value, so the warning about it goes
	// too. Same reasoning as Unset.
	return w.unmark(key)
}

// Reclassify records an explicit class for key in the project's entry in the
// central user schema, once the user authorises it through the prompt. Nothing
// is written if they decline.
//
// Two refusals land before the prompt, so the user is never made to authorise
// something that was going to fail anyway:
//
//   - global scope, where an override has no legitimate use;
//   - promoting a credential-shaped value to public, which Classify would
//     override on sight, leaving a schema entry that silently does nothing.
//
// A key that is secret only by *name* is fair game — correcting that is what
// this exists for.
func (w *W) Reclassify(key string, to classify.Class) error {
	if w.global {
		return fmt.Errorf("%s: %w", key, ErrGlobalScope)
	}
	if to == classify.Public {
		v, _ := w.st.Get(key)
		if rule, ok := classify.ShapeRule(v); ok {
			return fmt.Errorf("%s %w (%s)", key, ErrUnwaivableShape, rule)
		}
	}

	// Only the loosening direction demands the key be retyped, and only when
	// there is something to loosen. A key holding no value cannot disclose one,
	// so the retype there costs a dialog and buys nothing — and a ceremony that
	// fires when nothing is at stake is training to click through the one that
	// matters. Provisioning a new key is the common case; unmasking a live
	// secret is the rare one, and it still pays in full.
	retype := to == classify.Public && w.has(key)
	if err := w.p.Confirm(to.String(), key, w.SchemaPath(), retype); err != nil {
		return err
	}
	if _, err := classify.SetUserClass(w.home, w.projectDir, key, to); err != nil {
		return err
	}

	// Reload so this W stops serving the pre-write classification.
	sch, err := classify.LoadUserSchema(w.home, w.projectDir)
	if err != nil {
		return err
	}
	w.userSchema = sch
	return nil
}

// Loosen records key as public without a dialog, for the provisioning path
// behind `warden set --public`.
//
// It is quiet because passing the flag is itself the authorisation: the user
// named the class they want, on a key that holds nothing, in the same command
// as the value. Asking again would be asking them to confirm the flag they
// just typed.
//
// Everything that makes loosening dangerous is still refused here. A key that
// already holds a value goes to Reclassify and its retype — that is the case
// the ceremony exists for, and this must not become a way around it. Global
// scope is refused outright. And the value itself is still classified on the
// way in by SetPublic, where a credential shape outranks any override.
//
// The remaining guard is what the flag is scoped to: a key that is secret only
// because warden fails closed. That is the whole case this exists to serve — a
// name no rule recognised, defaulting to secret because defaulting the other
// way would be worse. A key that matched an actual rule is a different claim
// entirely: something identified it as a credential, and overriding that
// quietly, from the same command that supplies the value, is precisely the
// escalation the retype ceremony exists to slow down.
// It takes the value it is about to authorise, not just the key, so that every
// refusal happens before anything is persisted. Checking the value's shape
// afterwards in SetPublic would leave the override written and the command
// reporting failure — the operator is told no, and the key is public anyway.
func (w *W) Loosen(key, value string) error {
	if w.global {
		return fmt.Errorf("%s: %w", key, ErrGlobalScope)
	}
	if w.has(key) {
		return fmt.Errorf("%s %w", key, ErrHasValue)
	}
	if got := w.classOf(key); got.Class == classify.Secret && !got.FailClosed() {
		return fmt.Errorf("%s (%s) %w", key, got.Rule, ErrRuleMatched)
	}
	if rule, ok := classify.ShapeRule(secret.Secret(value)); ok {
		return fmt.Errorf("%s (%s): %w", key, rule, ErrUnwaivableShape)
	}
	if _, err := classify.SetUserClass(w.home, w.projectDir, key, classify.Public); err != nil {
		return err
	}
	sch, err := classify.LoadUserSchema(w.home, w.projectDir)
	if err != nil {
		return err
	}
	w.userSchema = sch
	return nil
}

func (w *W) classOf(key string) classify.Result {
	v, _ := w.st.Get(key)
	return classify.Classify(key, v, w.userSchema, w.projectSchema)
}

// has reports whether the destination store already holds a usable value for
// key. Push consults it so a push cannot silently overwrite a value the project
// is currently running on.
func (w *W) has(key string) bool {
	v, ok := w.st.Get(key)
	return ok && v.IsSet()
}

// setFromVault writes a value that came from the vault rather than from a
// prompt.
//
// It exists because Push must not go through SetSecret, which would ask the user
// to type a value warden is already holding, and must not go through SetPublic,
// which refuses credential-shaped values — refusing them is right for a caller
// handing warden a value, and wrong for warden moving its own. The value crosses
// as a secret.Secret and is exposed here, at one reviewed call site.
func (w *W) setFromVault(key string, v secret.Secret) error {
	return w.st.Set(key, v.Expose())
}
