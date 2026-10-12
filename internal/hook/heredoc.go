package hook

import (
	"path"
	"strings"
)

// stripHeredocBodies blanks the bodies of the command line's heredocs, so a
// guard judges what runs rather than the text a command reads. An agent writing
// a doc with `cat > notes.md <<'EOF'`, or a commit message with
// `git commit -m "$(cat <<'EOF'`, would otherwise be denied for prose that names
// .env beside a word like cat or sed.
//
// keep is asked about each line that opens heredocs, and a body it keeps is
// judged: `bash <<EOF` and `cat <<EOF | sh` feed the body to a shell, so there
// the body is the commands.
//
// The parse errs toward keeping text, because a misread that keeps a body costs a
// needless denial and one that drops a command lets a read through. It tracks quotes, command
// substitutions, comments, $((…)) and ${…}, so a << that is not an operator is
// not taken for one, and it hands back the command untouched whenever it is
// unsure: an unterminated heredoc or quote, a delimiter that would need
// expanding, a quoted newline before the body starts.
//
// The same parse is in hydra's heredoc.go, which matches rules against commands;
// a fix to one belongs in both.
func stripHeredocBodies(s string, keep func(line string) bool) string {
	if !strings.Contains(s, "<<") {
		return s
	}

	var out strings.Builder
	var stack []heredocFrame
	var pending []heredoc
	lineStart := 0

	for i := 0; i < len(s); {
		c := s[i]
		top := byte(0)
		if len(stack) > 0 {
			top = stack[len(stack)-1].kind
		}
		quoted := top == '"'

		switch {
		case c == '\\' && i+1 < len(s):
			out.WriteString(s[i : i+2])
			i += 2
			continue
		case c == '"' && quoted, c == '`' && top == '`':
			stack = stack[:len(stack)-1]
		case c == '"', c == '`':
			stack = append(stack, heredocFrame{kind: c})
		case strings.HasPrefix(s[i:], "$(("), strings.HasPrefix(s[i:], "${"),
			!quoted && strings.HasPrefix(s[i:], "(("):
			// Arithmetic and parameter expansion: a << in there is a shift or a
			// pattern, never an operator.
			end := closingBracket(s, i)
			if end < 0 {
				return s
			}
			out.WriteString(s[i:end])
			i = end
			continue
		case strings.HasPrefix(s[i:], "$("):
			stack = append(stack, heredocFrame{kind: '('})
			out.WriteString("$(")
			i += 2
			continue
		case c == '\n' && quoted && len(pending) > 0:
			return s
		case quoted:
			// Nothing else is special inside double quotes.
		case c == '\'' || strings.HasPrefix(s[i:], "$'"):
			end := closingQuote(s, i)
			if end < 0 || (len(pending) > 0 && strings.Contains(s[i:end], "\n")) {
				return s
			}
			out.WriteString(s[i:end])
			i = end
			continue
		case c == '#' && (i == 0 || strings.IndexByte(" \t\n;&|()", s[i-1]) >= 0):
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				end = len(s) - i
			}
			out.WriteString(s[i : i+end])
			i += end
			continue
		case c == '(' && top == '(':
			stack[len(stack)-1].parens++
		case c == ')' && top == '(':
			if stack[len(stack)-1].parens == 0 {
				stack = stack[:len(stack)-1]
			} else {
				stack[len(stack)-1].parens--
			}
		case strings.HasPrefix(s[i:], "<<<"):
			out.WriteString("<<<")
			i += 3
			continue
		case strings.HasPrefix(s[i:], "<<"):
			h, end, ok := parseHeredocOperator(s, i)
			if !ok {
				return s
			}
			pending = append(pending, h)
			out.WriteString(s[i:end])
			i = end
			continue
		case c == '\n' && len(pending) > 0:
			if keep(s[lineStart:i]) {
				pending = nil
				break
			}
			rest, ok := skipHeredocBodies(s, i+1, pending)
			if !ok {
				return s
			}
			out.WriteByte('\n')
			i, lineStart, pending = rest, rest, nil
			continue
		}
		if c == '\n' {
			lineStart = i + 1
		}
		out.WriteByte(c)
		i++
	}
	if len(stack) > 0 || len(pending) > 0 {
		return s
	}
	return out.String()
}

type heredoc struct {
	delim     string
	stripTabs bool // <<- strips leading tabs from body lines and the terminator
}

// heredocFrame is one open context: '"' double quotes, '`' backticks, or '(' a
// $( substitution, which counts the bare parentheses inside it.
type heredocFrame struct {
	kind   byte
	parens int
}

// closingBracket returns the index just past the bracket that closes the
// $((, (( or ${ at s[i], or -1 when none does.
func closingBracket(s string, i int) int {
	open, shut, depth, j := byte('('), byte(')'), 2, i+2
	switch {
	case strings.HasPrefix(s[i:], "${"):
		open, shut, depth = '{', '}', 1
	case s[i] == '$':
		j++
	}
	for ; j < len(s); j++ {
		switch s[j] {
		case open:
			depth++
		case shut:
			if depth--; depth == 0 {
				return j + 1
			}
		}
	}
	return -1
}

// closingQuote returns the index just past the quote that closes the '…' or
// $'…' at s[i], or -1 when none does. Only $'…' honours backslashes.
func closingQuote(s string, i int) int {
	escapes := s[i] == '$'
	for j := i + 1 + btoi(escapes); j < len(s); j++ {
		switch {
		case escapes && s[j] == '\\':
			j++
		case s[j] == '\'':
			return j + 1
		}
	}
	return -1
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// parseHeredocOperator reads the operator and delimiter word starting at s[i],
// which begins with "<<". It returns the index just past the delimiter. A
// delimiter the parse cannot settle — empty, or one that names a variable or a
// substitution — is not ok.
func parseHeredocOperator(s string, i int) (heredoc, int, bool) {
	var h heredoc
	j := i + 2
	if j < len(s) && s[j] == '-' {
		h.stripTabs = true
		j++
	}
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}

	var delim strings.Builder
	for j < len(s) {
		c := s[j]
		if c == '\'' || c == '"' {
			end := strings.IndexByte(s[j+1:], c)
			if end < 0 {
				return h, 0, false
			}
			delim.WriteString(s[j+1 : j+1+end])
			j += end + 2
			continue
		}
		if c == '\\' && j+1 < len(s) {
			delim.WriteByte(s[j+1])
			j += 2
			continue
		}
		if strings.IndexByte(" \t\n;&|<>()", c) >= 0 {
			break
		}
		delim.WriteByte(c)
		j++
	}
	h.delim = delim.String()
	ok := h.delim != "" && !strings.ContainsAny(h.delim, "$`")
	return h, j, ok
}

// skipHeredocBodies walks past each pending body in order, starting at the line
// after their operator. It reports where the command resumes, or false when a
// terminator is missing. A line that is the delimiter followed by ")" is taken
// as unsure too: some shells end a body there inside $(…), and others do not.
func skipHeredocBodies(s string, from int, pending []heredoc) (int, bool) {
	pos := from
	for _, h := range pending {
		for {
			if pos >= len(s) {
				return 0, false
			}
			end := strings.IndexByte(s[pos:], '\n')
			line, next := s[pos:], len(s)
			if end >= 0 {
				line, next = s[pos:pos+end], pos+end+1
			}
			if h.stripTabs {
				line = strings.TrimLeft(line, "\t")
			}
			pos = next
			if line == h.delim {
				break
			}
			if strings.HasPrefix(line, h.delim+")") {
				return 0, false
			}
		}
	}
	return pos, true
}

// heredocWords splits a line into the base names of its words, so /bin/bash,
// "$(bash" and bash all read as bash.
func heredocWords(line string) []string {
	words := strings.FieldsFunc(line, func(r rune) bool {
		return strings.ContainsRune(" \t;&|(){}<>`\"'$", r)
	})
	for i, w := range words {
		words[i] = path.Base(w)
	}
	return words
}

// heredocShells run a heredoc's body as commands. parallel runs each line.
var heredocShells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
	"ssh": true, "eval": true, "source": true, ".": true, "parallel": true,
}

// bodyRunsAsShell is the guard's keep. A body is judged when its operator line,
// spelled as the shell will spell it, may run it: a shell named anywhere on the
// line (bash <<EOF, cat <<EOF | sh, bash -c "$(cat <<EOF"), or a command whose
// name is computed ($sh <<EOF), which could be one.
//
// A body that only names files, as in xargs cat <<EOF, is left out; a body line
// holding a bare name was never judged a read before heredocs were parsed either,
// since no reader shares its line. What stays open is the package doc's limit: a
// body written to a script that a later command runs names no env file there.
func bodyRunsAsShell(line string) bool {
	line = normalizeShell(line)
	for _, cmd := range strings.FieldsFunc(line, func(r rune) bool {
		return strings.ContainsRune(";&|(){}\n", r)
	}) {
		for _, w := range strings.Fields(cmd) {
			if strings.Contains(w, "=") && !strings.HasPrefix(w, "-") {
				continue // an assignment ahead of the command
			}
			if strings.HasPrefix(w, "$") || strings.HasPrefix(w, "`") {
				return true
			}
			break
		}
	}
	for _, w := range heredocWords(line) {
		if heredocShells[w] {
			return true
		}
	}
	return false
}
