// Package query is the read path from stored configuration to the outside
// world, and the only one.
//
// Every method here returns booleans, key names, or classifications. Get is the
// single exception, and it returns a value only after classify has said the key
// is public. internal/cli and internal/mcpserver import this package and never
// internal/store, so no surface can reach a raw value without a classification.
package query

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/webteractive/warden/internal/classify"
	"github.com/webteractive/warden/internal/store"
)

var (
	// ErrSecret means the key exists but may not be revealed.
	ErrSecret = errors.New("key is secret")
	// ErrNotSet means the key is absent or empty.
	ErrNotSet = errors.New("key is not set")
	// ErrGlobalUnsupported means the operation has no meaning for ~/.secrets.
	ErrGlobalUnsupported = errors.New("not supported in global scope")
	// ErrNoFile means there is no env file to open. It is the store's error,
	// re-exported so callers that may not import store can recognise it.
	ErrNoFile = store.ErrNoFile
)

// Scope selects which store to open.
type Scope struct {
	// Global targets $HOME/.secrets instead of a project .env.
	Global bool
	// Dir is where the search for a project .env starts.
	Dir string
	// Home is the user's home directory.
	Home string
}

// Q is an open, read-only view of one store.
type Q struct {
	st            store.Store
	userSchema    *classify.Schema
	projectSchema *classify.Schema
	global        bool
	dir           string
	home          string
	projectDir    string
}

// Open resolves the scope and loads the central and legacy project schemas.
func Open(sc Scope) (*Q, error) {
	q := &Q{global: sc.Global, dir: sc.Dir, home: sc.Home}
	var err error
	if sc.Global {
		q.st, err = store.OpenSecrets(sc.Home)
	} else {
		q.st, err = store.OpenDotenv(sc.Dir)
	}
	if err != nil {
		return nil, err
	}
	// Both schema layers identify the project by the directory containing the
	// resolved .env, not by the caller's cwd.
	if !sc.Global {
		projectDir := filepath.Dir(q.st.Path())
		q.projectDir, err = classify.CanonicalProjectRoot(projectDir)
		if err != nil {
			return nil, err
		}
		q.userSchema, err = classify.LoadUserSchema(sc.Home, projectDir)
		if err != nil {
			return nil, err
		}
		q.projectSchema, err = classify.LoadSchema(projectDir)
		if err != nil {
			return nil, err
		}
	}
	return q, nil
}

// Path is the backing file, safe to show a user.
func (q *Q) Path() string { return q.st.Path() }

// Has reports whether the key is present and non-empty. It works for secret
// keys as readily as public ones — answering this without revealing anything is
// the reason Warden exists.
func (q *Q) Has(key string) bool {
	v, ok := q.st.Get(key)
	return ok && v.IsSet()
}

// Row is one key's public-facing summary. It deliberately has no value field.
type Row struct {
	Key   string
	Class classify.Class
	Set   bool
}

// List summarises every assigned key in file order.
func (q *Q) List() []Row {
	keys := q.st.Keys()
	rows := make([]Row, 0, len(keys))
	for _, k := range keys {
		v, _ := q.st.Get(k)
		rows = append(rows, Row{
			Key:   k,
			Class: classify.Classify(k, v, q.userSchema, q.projectSchema).Class,
			Set:   v.IsSet(),
		})
	}
	return rows
}

// Classify explains a key's sensitivity and which rule decided it.
func (q *Q) Classify(key string) classify.Result {
	v, _ := q.st.Get(key)
	return classify.Classify(key, v, q.userSchema, q.projectSchema)
}

// Get returns a value, but only for a public key. The error deliberately
// mentions the key and never the value.
func (q *Q) Get(key string) (string, error) {
	v, ok := q.st.Get(key)
	if !ok || !v.IsSet() {
		return "", fmt.Errorf("%s: %w", key, ErrNotSet)
	}
	if classify.Classify(key, v, q.userSchema, q.projectSchema).Class == classify.Secret {
		return "", fmt.Errorf("%s: %w", key, ErrSecret)
	}
	return v.Expose(), nil
}

// Missing lists keys declared in .env.example that are absent or empty in .env,
// preserving the example file's order.
func (q *Q) Missing() ([]string, error) {
	if q.global {
		return nil, fmt.Errorf("missing: %w — ~/.secrets has no .env.example", ErrGlobalUnsupported)
	}
	declared, err := store.ExampleKeys(q.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, k := range declared {
		if !q.Has(k) {
			out = append(out, k)
		}
	}
	return out, nil
}
