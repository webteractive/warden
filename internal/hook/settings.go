package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// tagKey marks the entry warden owns, so uninstall and re-install can find
// exactly it and leave every other hook alone.
const tagKey = "_warden"

// tagValue names what the entry does, in case a human reads the settings file
// and wonders where it came from.
const tagValue = "env-read-guard"

// Matcher is the tool set the guard is asked about. Everything else is
// irrelevant to it and should not pay the cost of a subprocess.
const Matcher = "Read|Edit|Write|NotebookEdit|Grep|Bash|Monitor|LSP"

// Entry is the PreToolUse entry warden installs.
func Entry(command string) map[string]any {
	return map[string]any{
		tagKey:    tagValue,
		"matcher": Matcher,
		"hooks": []any{
			map[string]any{"type": "command", "command": command},
		},
	}
}

// EntryJSON renders the entry for printing, which is the default mode: a
// command that silently edits a settings file is one nobody trusts twice.
func EntryJSON(command string) (string, error) {
	b, err := json.MarshalIndent(map[string]any{
		"hooks": map[string]any{"PreToolUse": []any{Entry(command)}},
	}, "", "  ")
	return string(b), err
}

// load reads a settings file, treating absence as an empty document and a parse
// failure as a refusal. Repairing somebody's JSON is not warden's business.
func load(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return map[string]any{}, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON (%w) — warden will not rewrite it", path, err)
	}
	return doc, nil
}

// save writes the document atomically, so an interrupted install cannot leave a
// truncated settings file behind.
func save(path string, doc map[string]any) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".warden-settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// entries returns the PreToolUse list and the hooks map holding it.
func entries(doc map[string]any) (map[string]any, []any) {
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	list, _ := hooks["PreToolUse"].([]any)
	return hooks, list
}

func isWardens(v any) bool {
	e, ok := v.(map[string]any)
	return ok && e[tagKey] == tagValue
}

// Install adds or replaces warden's entry, preserving everything else.
func Install(path, command string) error {
	doc, err := load(path)
	if err != nil {
		return err
	}
	hooks, list := entries(doc)

	kept := make([]any, 0, len(list)+1)
	for _, e := range list {
		if !isWardens(e) {
			kept = append(kept, e)
		}
	}
	kept = append(kept, Entry(command))

	hooks["PreToolUse"] = kept
	doc["hooks"] = hooks
	return save(path, doc)
}

// Uninstall removes warden's entry and leaves every other hook untouched.
func Uninstall(path string) (bool, error) {
	doc, err := load(path)
	if err != nil {
		return false, err
	}
	hooks, list := entries(doc)

	kept := make([]any, 0, len(list))
	removed := false
	for _, e := range list {
		if isWardens(e) {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	if !removed {
		return false, nil
	}
	hooks["PreToolUse"] = kept
	doc["hooks"] = hooks
	return true, save(path, doc)
}

// Installed reports whether warden's entry is present.
func Installed(path string) bool {
	doc, err := load(path)
	if err != nil {
		return false
	}
	_, list := entries(doc)
	for _, e := range list {
		if isWardens(e) {
			return true
		}
	}
	return false
}
