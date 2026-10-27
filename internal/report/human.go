// Package report renders a core.Result for people (Human) and, from
// milestone 3, for programs (JSON).
package report

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// Options controls human output.
type Options struct {
	Verbose bool
	Quiet   bool
}

// Human writes the verdict, chain table, explanation and fixes.
func Human(w io.Writer, r *core.Result, o Options) error {
	r = escapePaths(r)
	var b strings.Builder
	b.WriteString(verdictLine(r) + "\n")
	if !o.Quiet {
		section(&b, "", chainTable(r))
		if o.Verbose {
			section(&b, "Checks", passing(r))
		}
		section(&b, "Why", why(r))
		section(&b, fixesHeading(r), fixes(r))
		section(&b, "Also noticed", noticed(r))
	}
	_, err := io.WriteString(w, sanitize(b.String()))
	return err
}

// escapePaths returns a copy of r in which paths containing control
// characters (such as a newline in a file name) are shown escaped, so they
// cannot break the layout. Fix commands are left alone: they are already
// quoted exactly.
func escapePaths(r *core.Result) *core.Result {
	var pairs []string
	seen := map[string]bool{}
	addPath := func(p string) {
		if !seen[p] && strings.ContainsFunc(p, unicode.IsControl) {
			seen[p] = true
			pairs = append(pairs, p, escapeControl(p))
		}
	}
	addPath(r.Path)
	for _, n := range r.Chain {
		addPath(n.Path)
	}
	if len(pairs) == 0 {
		return r
	}
	rep := strings.NewReplacer(pairs...)
	out := *r
	out.Path = rep.Replace(r.Path)
	out.Chain = make([]*core.Node, len(r.Chain))
	for i, n := range r.Chain {
		c := *n
		c.Path = rep.Replace(n.Path)
		out.Chain[i] = &c
	}
	out.Findings = make([]core.Finding, len(r.Findings))
	for i, f := range r.Findings {
		f.NodePath = rep.Replace(f.NodePath)
		f.Summary = rep.Replace(f.Summary)
		f.Detail = rep.Replace(f.Detail)
		out.Findings[i] = f
	}
	return &out
}

func escapeControl(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case unicode.IsControl(r):
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitize escapes control characters other than newline, so hostile file
// names cannot inject terminal escape sequences or rewrite earlier lines.
func sanitize(s string) string {
	if !strings.ContainsFunc(s, isControl) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if isControl(r) {
			fmt.Fprintf(&b, "\\x%02x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isControl(r rune) bool { return r != '\n' && unicode.IsControl(r) }

func section(b *strings.Builder, heading, body string) {
	if body == "" {
		return
	}
	b.WriteString("\n")
	if heading != "" {
		b.WriteString(heading + "\n")
	}
	b.WriteString(body)
}

func verdictLine(r *core.Result) string {
	who := r.Subject.Display()
	switch r.Verdict {
	case core.Allowed:
		return fmt.Sprintf("✓ %s can %s %s", who, r.Action, r.Path)
	case core.Denied:
		if r.Confidence != core.Certain {
			return fmt.Sprintf("✗ %s probably cannot %s %s", who, r.Action, r.Path)
		}
		return fmt.Sprintf("✗ %s cannot %s %s", who, r.Action, r.Path)
	}
	return fmt.Sprintf("? could not determine whether %s can %s %s", who, r.Action, r.Path)
}

func chainTable(r *core.Result) string {
	pathW, modeW, ownerW := 0, 0, 0
	for _, n := range r.Chain {
		pathW = max(pathW, width(n.Path))
		if n.Evaluated && n.Exists {
			modeW = max(modeW, width(modeString(n)))
			ownerW = max(ownerW, width(owner(n)))
		}
	}
	pathW += 3
	modeW = max(modeW, len("drwxr-xr-x")) + 2
	if ownerW > 0 {
		ownerW += 2
	}

	worst := worstFindings(r)
	var b strings.Builder
	for _, n := range r.Chain {
		b.WriteString("  " + pad(n.Path, pathW))
		if !n.Evaluated {
			b.WriteString(pad("·", modeW) + "not evaluated\n")
			continue
		}
		if n.Exists {
			b.WriteString(pad(modeString(n), modeW) + pad(owner(n), ownerW))
		} else {
			b.WriteString(pad("·", modeW) + pad("", ownerW))
		}
		b.WriteString(mark(n.Result) + " " + rowWord(r, n, worst[n.Path]))
		switch n.Result {
		case core.Blocker:
			b.WriteString("   ← blocked here")
		case core.Unknown:
			b.WriteString("   ← cannot see past here")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// modeString is the ls-style mode, with "+" when an ACL is present and the
// immutable/append-only attributes in brackets.
func modeString(n *core.Node) string {
	s := n.Info.ModeString()
	if n.ACL != nil {
		s += "+"
	}
	var flags string
	if n.Flags&sys.FlagImmutable != 0 {
		flags += "i"
	}
	if n.Flags&sys.FlagAppendOnly != 0 {
		flags += "a"
	}
	if flags != "" {
		s += " [" + flags + "]"
	}
	return s
}

func owner(n *core.Node) string { return n.OwnerName + ":" + n.GroupName }

func mark(s core.Severity) string {
	switch s {
	case core.Blocker:
		return "✗"
	case core.Unknown:
		return "?"
	case core.Warn:
		return "!"
	}
	return "✓"
}

// rowWord is what the node was checked for, or what is wrong with the path
// itself (missing, wrong type).
func rowWord(r *core.Result, n *core.Node, worst *core.Finding) string {
	if worst != nil && worst.Check == "path" && worst.Severity >= core.Unknown {
		if errors.Is(n.Err, fs.ErrPermission) {
			return "cannot inspect"
		}
		return worst.Summary
	}
	switch n.Role {
	case core.RoleSymlink:
		return "→ " + n.Info.LinkTarget
	case core.RoleParent:
		if r.Action == core.Create {
			return "create in"
		}
		return "delete from"
	case core.RoleTarget:
		if !n.Exists && r.Action == core.Create {
			return "new entry"
		}
		return r.Action.String()
	case core.RoleInterpreter:
		return "interpreter"
	case core.RoleLoader:
		return "loader"
	}
	return "traverse"
}

func worstFindings(r *core.Result) map[string]*core.Finding {
	out := map[string]*core.Finding{}
	for i := range r.Findings {
		f := &r.Findings[i]
		if cur, ok := out[f.NodePath]; !ok || f.Severity > cur.Severity {
			out[f.NodePath] = f
		}
	}
	return out
}

func blocking(r *core.Result) []core.Finding {
	var out []core.Finding
	for _, f := range r.Findings {
		if f.Severity >= core.Unknown {
			out = append(out, f)
		}
	}
	return out
}

func why(r *core.Result) string {
	bs := blocking(r)
	if len(bs) == 1 {
		return indent(bs[0].Detail, "  ")
	}
	var b strings.Builder
	for i, f := range bs {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("  " + f.NodePath + ": " + f.Summary + "\n")
		b.WriteString(indent(f.Detail, "    "))
	}
	return b.String()
}

func fixesHeading(r *core.Result) string {
	if len(blocking(r)) > 1 {
		return "Fixes (safest first, for each problem)"
	}
	return "Fixes (safest first)"
}

func fixes(r *core.Result) string {
	bs := blocking(r)
	var b strings.Builder
	num := 0
	shown := map[string]bool{}
	for _, f := range bs {
		var fixes []core.Fix
		for _, fx := range f.Fixes {
			key := strings.Join(fx.Commands, "\n")
			if key != "" && shown[key] {
				continue // the same command was already suggested for another problem
			}
			shown[key] = true
			fixes = append(fixes, fx)
		}
		if len(fixes) == 0 {
			continue
		}
		if len(bs) > 1 {
			b.WriteString("  " + f.NodePath + ":\n")
		}
		for _, fx := range fixes {
			num++
			desc := fx.Description
			if fx.Note != "" {
				desc += " (" + fx.Note + ")"
			}
			if len(fx.Commands) == 0 {
				fmt.Fprintf(&b, "  %d. %s.\n", num, desc)
				continue
			}
			fmt.Fprintf(&b, "  %d. %s:\n", num, desc)
			for _, c := range fx.Commands {
				b.WriteString("       " + c + "\n")
			}
		}
	}
	return b.String()
}

func noticed(r *core.Result) string {
	var b strings.Builder
	for _, f := range r.Findings {
		if f.Severity != core.Warn && f.Severity != core.Info {
			continue
		}
		b.WriteString("  " + f.NodePath + ": " + f.Summary + "\n")
		b.WriteString(indent(f.Detail, "    "))
	}
	return b.String()
}

func passing(r *core.Result) string {
	var b strings.Builder
	for _, f := range r.Findings {
		if f.Severity == core.Pass {
			fmt.Fprintf(&b, "  ✓ %-5s %s: %s\n", f.Check, f.NodePath, f.Summary)
		}
	}
	return b.String()
}

func indent(text, prefix string) string {
	if text == "" {
		return ""
	}
	var b strings.Builder
	for line := range strings.SplitSeq(text, "\n") {
		b.WriteString(prefix + line + "\n")
	}
	return b.String()
}

func width(s string) int { return utf8.RuneCountInString(s) }

func pad(s string, w int) string {
	if n := width(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}
