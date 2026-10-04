package classify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Claude Code mod scans tool output for credentials with free-text forms of
// these same rules (integrations/claude-code/hooks/shapes.ts). A shape added
// here and not there would be recognised in an env file and missed in a tool
// result, so every prefix and rule name must appear in that file.
func TestTheModRecognisesEveryValueShape(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "integrations", "claude-code", "hooks", "shapes.ts"))
	if err != nil {
		t.Skipf("no mod beside this checkout: %v", err)
	}
	shapes := string(src)
	for _, s := range shapePrefixes {
		if !strings.Contains(shapes, "'"+s.prefix) && !strings.Contains(shapes, s.prefix) {
			t.Errorf("shapes.ts has no rule for prefix %q (%s)", s.prefix, s.rule)
		}
		if !strings.Contains(shapes, "'"+s.rule+"'") {
			t.Errorf("shapes.ts does not name rule %q", s.rule)
		}
	}
	if !strings.Contains(shapes, "'shape:url-userinfo'") {
		t.Error("shapes.ts does not name rule shape:url-userinfo")
	}
}
