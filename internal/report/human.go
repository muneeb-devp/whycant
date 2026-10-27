// Package report renders a core.Result for people (Human) and for programs
// (JSON).
package report

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"unicode"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// Options controls human output.
type Options struct {
	Verbose bool
	Quiet   bool
	Color   bool
	// ASCII replaces symbols such as ✓ and ← for terminals without UTF-8.
	ASCII bool
	// Width is the terminal width; when set, long paths in the chain table
	// are shortened in the middle and prose is wrapped. 0 means no limit.
	Width int
}

// Styles are inserted as private-use runes while the text is built, so that
// sanitizing hostile content cannot touch them, and are turned into ANSI
// sequences (or nothing) at the end.
const (
	styleReset = '' + iota
	styleRed
	styleGreen
	styleYellow
	styleBold
	styleCyan
	styleDim
)

var ansi = map[rune]string{
	styleReset:  "\x1b[0m",
	styleRed:    "\x1b[31m",
	styleGreen:  "\x1b[32m",
	styleYellow: "\x1b[33m",
	styleBold:   "\x1b[1m",
	styleCyan:   "\x1b[36m",
	styleDim:    "\x1b[2m",
}

func style(st rune, s string) string { return string(st) + s + string(styleReset) }

var asciiReplacer = strings.NewReplacer("✓", "OK", "✗", "NO", "←", "<-", "→", "->", "·", ".", "…", "...")

type renderer struct {
	Options
	r *core.Result
}

// Human writes the verdict, chain table, explanation and fixes.
func Human(w io.Writer, r *core.Result, o Options) error {
	h := renderer{Options: o, r: escapePaths(r)}
	var b strings.Builder
	b.WriteString(h.verdictLine() + "\n")
	if !o.Quiet {
		h.section(&b, "", h.chainTable())
		if o.Verbose {
			h.section(&b, "Checks", h.passing())
		}
		h.section(&b, "Why", h.why())
		h.section(&b, h.fixesHeading(), h.fixes())
		h.section(&b, "Also noticed", h.noticed())
		h.section(&b, "Verify", h.verify())
	}
	out := sanitize(b.String())
	if o.ASCII {
		out = asciiReplacer.Replace(out)
	}
	out = strings.Map(func(r rune) rune {
		if _, ok := ansi[r]; ok && !o.Color {
			return -1
		}
		return r
	}, out)
	if o.Color {
		for st, code := range ansi {
			out = strings.ReplaceAll(out, string(st), code)
		}
	}
	_, err := io.WriteString(w, out)
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

func (h *renderer) section(b *strings.Builder, heading, body string) {
	if body == "" {
		return
	}
	b.WriteString("\n")
	if heading != "" {
		b.WriteString(style(styleBold, heading) + "\n")
	}
	b.WriteString(body)
}

func (h *renderer) verdictLine() string {
	r := h.r
	who := r.Subject.Display()
	switch r.Verdict {
	case core.Allowed:
		return style(styleGreen, "✓") + style(styleBold, fmt.Sprintf(" %s can %s %s", who, r.Action, r.Path))
	case core.Denied:
		verb := "cannot"
		if r.Confidence != core.Certain {
			verb = "probably cannot"
		}
		return style(styleRed, "✗") + style(styleBold, fmt.Sprintf(" %s %s %s %s", who, verb, r.Action, r.Path))
	}
	return style(styleYellow, "?") + style(styleBold, fmt.Sprintf(" could not determine whether %s can %s %s", who, r.Action, r.Path))
}

func (h *renderer) chainTable() string {
	r := h.r
	pathW, modeW, ownerW, wordW := 0, 0, 0, 0
	worst := worstFindings(r)
	for _, n := range r.Chain {
		pathW = max(pathW, width(n.Path))
		if n.Evaluated && n.Exists {
			modeW = max(modeW, width(modeString(n)))
			ownerW = max(ownerW, width(owner(n)))
		}
		if n.Evaluated {
			wordW = max(wordW, width(rowWord(r, n, worst[n.Path])))
		}
	}
	modeW = max(modeW, len("drwxr-xr-x")) + 2
	if ownerW > 0 {
		ownerW += 2
	}
	if h.Width > 0 {
		// Leave room for the other columns and the marker; shorten paths.
		room := h.Width - 2 - 3 - modeW - ownerW - 2 - min(wordW, 20) - len("   ← blocked here")
		pathW = min(pathW, max(room, 16))
	}
	pathW += 3

	var b strings.Builder
	for _, n := range r.Chain {
		b.WriteString("  " + pad(truncateMiddle(n.Path, pathW-3), pathW))
		if !n.Evaluated {
			b.WriteString(pad("·", modeW) + style(styleDim, "not evaluated") + "\n")
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
			b.WriteString(style(styleRed, "   ← blocked here"))
		case core.Unknown:
			b.WriteString(style(styleYellow, "   ← cannot see past here"))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// truncateMiddle shortens a path to w characters as "/very/…/long/path",
// keeping the first component and as many whole trailing components as fit.
func truncateMiddle(p string, w int) string {
	if width(p) <= w || w < 8 {
		return p
	}
	comps := strings.Split(strings.TrimPrefix(p, "/"), "/")
	build := func(head string) string {
		tail := ""
		for i := len(comps) - 1; i > 0; i-- {
			next := comps[i]
			if tail != "" {
				next += "/" + tail
			}
			if width(head+"…/"+next) > w {
				break
			}
			tail = next
		}
		if tail == "" {
			return ""
		}
		return head + "…/" + tail
	}
	if s := build("/" + comps[0] + "/"); s != "" {
		return s
	}
	if s := build(""); s != "" {
		return s
	}
	r := []rune(p)
	return "…" + string(r[len(r)-(w-1):])
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
		return style(styleRed, "✗")
	case core.Unknown:
		return style(styleYellow, "?")
	case core.Warn:
		return style(styleYellow, "!")
	}
	return style(styleGreen, "✓")
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

func (h *renderer) why() string {
	bs := blocking(h.r)
	if len(bs) == 1 {
		return h.indent(bs[0].Detail, "  ")
	}
	var b strings.Builder
	for i, f := range bs {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("  " + f.NodePath + ": " + f.Summary + "\n")
		b.WriteString(h.indent(f.Detail, "    "))
	}
	return b.String()
}

func (h *renderer) fixesHeading() string {
	if len(blocking(h.r)) > 1 {
		return "Fixes (safest first, for each problem)"
	}
	return "Fixes (safest first)"
}

func (h *renderer) fixes() string {
	bs := blocking(h.r)
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
			prefix := fmt.Sprintf("  %d. ", num)
			if len(fx.Commands) == 0 {
				b.WriteString(h.wrap(prefix+desc+".", strings.Repeat(" ", len(prefix))) + "\n")
				continue
			}
			b.WriteString(h.wrap(prefix+desc+":", strings.Repeat(" ", len(prefix))) + "\n")
			for _, c := range fx.Commands {
				b.WriteString("       " + style(styleCyan, c) + "\n")
			}
		}
	}
	return b.String()
}

func (h *renderer) noticed() string {
	var b strings.Builder
	for _, f := range h.r.Findings {
		if f.Severity != core.Warn && f.Severity != core.Info {
			continue
		}
		b.WriteString("  " + f.NodePath + ": " + f.Summary + "\n")
		b.WriteString(h.indent(f.Detail, "    "))
	}
	return b.String()
}

func (h *renderer) passing() string {
	var b strings.Builder
	for _, f := range h.r.Findings {
		if f.Severity == core.Pass {
			fmt.Fprintf(&b, "  %s %-9s %s: %s\n", style(styleGreen, "✓"), f.Check, f.NodePath, f.Summary)
		}
	}
	return b.String()
}

func (h *renderer) verify() string {
	v := h.r.Verify
	switch {
	case v == nil:
		return ""
	case v.Error != "":
		return "  " + style(styleYellow, "?") + " the kernel check could not run: " + v.Error + "\n"
	case v.Match:
		return fmt.Sprintf("  %s the kernel agrees: access(2) as %s says %s\n", style(styleGreen, "✓"), h.r.Subject.Who(), v.Probe)
	}
	return fmt.Sprintf("  %s the kernel disagrees: access(2) as %s says %s, but whycant says %s.\n"+
		"    This is a whycant bug. Please report it with the --json output:\n"+
		"    https://github.com/muneeb-devp/whycant/issues\n",
		style(styleRed, "✗"), h.r.Subject.Who(), v.Probe, h.r.Verdict)
}

// indent prefixes every line of text. With a width set and a line that does
// not fit, the text is reflowed as one paragraph at that width.
func (h *renderer) indent(text, prefix string) string {
	if text == "" {
		return ""
	}
	if h.Width > 0 {
		for line := range strings.SplitSeq(text, "\n") {
			if width(prefix+line) > h.Width {
				return h.wrap(prefix+strings.Join(strings.Fields(text), " "), prefix) + "\n"
			}
		}
	}
	var b strings.Builder
	for line := range strings.SplitSeq(text, "\n") {
		b.WriteString(h.wrap(prefix+line, prefix) + "\n")
	}
	return b.String()
}

// wrap breaks line at spaces to fit the width, continuing with prefix.
func (h *renderer) wrap(line, prefix string) string {
	if h.Width <= 0 || width(line) <= h.Width {
		return line
	}
	words := strings.Fields(line)
	var b strings.Builder
	cur := line[:len(line)-len(strings.TrimLeft(line, " "))] // keep the indentation
	curW := width(cur)
	first := true
	for _, w := range words {
		ww := width(w)
		switch {
		case first:
			cur += w
			curW += ww
			first = false
		case curW+1+ww > h.Width:
			b.WriteString(cur + "\n")
			cur, curW = prefix+w, width(prefix)+ww
		default:
			cur += " " + w
			curW += 1 + ww
		}
	}
	b.WriteString(cur)
	return b.String()
}

func width(s string) int {
	n := 0
	for _, r := range s {
		if _, ok := ansi[r]; !ok {
			n++
		}
	}
	return n
}

func pad(s string, w int) string {
	if n := width(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}
