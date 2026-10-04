package hook

import (
	"path"
	"regexp"
	"strconv"
	"strings"
)

// The shell reads a file under spellings a literal match never sees: .e""nv,
// .\env, $'\x2eenv', a variable set earlier in the same command. normalizeShell
// rewrites a command toward the spelling the shell acts on, so the checks in
// decide.go judge that rather than the text as typed.
//
// It narrows the gap; it cannot close it. A name computed at run time — the
// output of a substitution, eval, a value read from a file, a script — is not
// knowable without running the command, and that stays the speed-bump limit
// the package doc describes. What is handled here is the cheap class: literal
// obfuscation that spells a fixed name differently.
func normalizeShell(cmd string) string {
	cmd = decodeANSIC(cmd)
	cmd = substituteVariables(cmd)
	return dequote(cmd)
}

// ansiCRe matches bash's $'...' quoting, whose escapes spell any byte.
var ansiCRe = regexp.MustCompile(`\$'((?:[^'\\]|\\.)*)'`)

// decodeANSIC replaces each $'...' with the text it stands for.
func decodeANSIC(cmd string) string {
	return ansiCRe.ReplaceAllStringFunc(cmd, func(m string) string {
		return unescapeANSIC(ansiCRe.FindStringSubmatch(m)[1])
	})
}

var ansiCSimple = map[byte]string{
	'n': "\n", 't': "\t", 'r': "\r", 'a': "\a", 'b': "\b", 'f': "\f", 'v': "\v",
	'e': "\x1b", 'E': "\x1b", '\\': "\\", '\'': "'", '"': "\"", '?': "?",
}

func unescapeANSIC(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		c := s[i]
		if simple, ok := ansiCSimple[c]; ok {
			b.WriteString(simple)
			continue
		}
		switch {
		case c == 'x' || c == 'u' || c == 'U':
			width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
			j := i + 1
			for j < len(s) && j-i-1 < width && strings.IndexByte("0123456789abcdefABCDEF", s[j]) >= 0 {
				j++
			}
			if n, err := strconv.ParseUint(s[i+1:j], 16, 32); err == nil {
				b.WriteRune(rune(n))
				i = j - 1
				continue
			}
			b.WriteByte(c)
		case c >= '0' && c <= '7':
			j := i
			for j < len(s) && j-i < 3 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			n, _ := strconv.ParseUint(s[i:j], 8, 8)
			b.WriteByte(byte(n))
			i = j - 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// assignRe matches NAME=value, alone or after export, local, readonly or
// declare. forRe matches the list a for loop walks.
var (
	assignRe = regexp.MustCompile(`(?:^|[\s;&|(])(?:(?:export|local|readonly|declare(?:\s+-\w+)*)\s+)?([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|)]*)`)
	forRe    = regexp.MustCompile(`\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;&|\n]*)`)
)

// substituteVariables replaces $NAME and ${NAME} with every value the same
// command gives NAME, so `f=.env; cat $f` is judged as `cat .env`. All values
// stand in at once: which one a reference sees depends on order the shell
// decides, and naming every candidate errs toward the denial.
func substituteVariables(cmd string) string {
	values := map[string][]string{}
	for _, m := range assignRe.FindAllStringSubmatch(cmd, -1) {
		values[m[1]] = append(values[m[1]], dequote(m[2]))
	}
	for _, m := range forRe.FindAllStringSubmatch(cmd, -1) {
		values[m[1]] = append(values[m[1]], dequote(m[2]))
	}
	for name, vals := range values {
		ref := regexp.MustCompile(`\$\{` + name + `(?:[:#%/^,][^}]*)?\}|\$` + name + `\b`)
		cmd = ref.ReplaceAllLiteralString(cmd, strings.Join(vals, " "))
	}
	return cmd
}

// dequote drops the quotes and backslashes that change how a word is spelled
// but not which file it names: .e""nv and .\env are both .env to the shell.
func dequote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			continue
		case '\\':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// globTargetOf reports the protected file a shell word or glob can select once
// braces and wildcards are expanded, or "". A wildcard only counts when the
// pattern starts where a dotfile does: a bare * leaves dotfiles out, and
// denying it would deny every command that globs a directory.
func globTargetOf(word string) Target {
	alts, cut := expandBraces(strings.ToLower(word))
	if cut {
		return overflowTarget(word)
	}
	var target Target
	for _, alt := range alts {
		base := path.Base(alt)
		if IsProtected(base) {
			target = stricter(target, targetOf(base))
			continue
		}
		if !strings.ContainsAny(base, "*?[") || !strings.ContainsAny(base[:1], ".[?") {
			continue
		}
		for _, name := range globCandidates {
			if ok, _ := path.Match(base, name); ok {
				target = stricter(target, targetOf(name))
			}
		}
	}
	return target
}
