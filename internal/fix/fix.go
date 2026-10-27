// Package fix builds copy-paste-safe fix commands and ranks fixes.
package fix

import (
	"slices"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
)

// Quote returns s quoted for a POSIX shell. Strings made only of safe
// characters are returned as is, so common commands stay readable.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool { return !isSafe(r) }) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isSafe(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
		strings.ContainsRune("@%+=:,./_-", r)
}

// Command joins args into a shell command, quoting each one and prefixing
// sudo when asked. Paths passed to it are absolute, so they cannot be
// mistaken for options.
func Command(sudo bool, args ...string) string {
	quoted := make([]string, 0, len(args)+1)
	if sudo {
		quoted = append(quoted, "sudo")
	}
	for _, a := range args {
		quoted = append(quoted, Quote(a))
	}
	return strings.Join(quoted, " ")
}

// Rank orders fixes safest first, keeping the order of equal-risk fixes.
func Rank(fixes []core.Fix) {
	slices.SortStableFunc(fixes, func(a, b core.Fix) int { return int(a.Risk) - int(b.Risk) })
}
