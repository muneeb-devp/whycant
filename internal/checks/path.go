package checks

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"syscall"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
)

// Path reports components that are missing, of the wrong type, or that
// whycant itself cannot inspect.
type Path struct{}

// Name implements Check.
func (Path) Name() string { return "path" }

// Applies implements Check.
func (Path) Applies(_ *Context, n *core.Node) bool { return n.Exists || n.Err != nil }

// Evaluate implements Check.
func (Path) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	f := core.Finding{Check: "path", NodePath: n.Path, Confidence: core.Certain}
	switch {
	case n.Err != nil:
		return []core.Finding{inspectError(ctx, n, f)}

	case n.Role == core.RoleSymlink:
		f.Severity = core.Pass
		f.Summary = "symbolic link to " + n.Info.LinkTarget

	case (n.Role == core.RoleAncestor || n.Role == core.RoleParent) && !n.Info.IsDir():
		f.Severity = core.Blocker
		f.Summary = "not a directory"
		f.Detail = fmt.Sprintf("%s is a %s, not a directory, so nothing can exist beneath it.", n.Path, typeName(n.Info))

	case n.Role == core.RoleTarget:
		return targetType(ctx, n, f)

	default:
		return nil
	}
	return []core.Finding{f}
}

func inspectError(ctx *Context, n *core.Node, f core.Finding) core.Finding {
	switch {
	case errors.Is(n.Err, fs.ErrNotExist) && n.Role == core.RoleTarget && ctx.Action == core.Create:
		f.Severity = core.Pass
		f.Summary = "does not exist yet, so it would be created"
	case errors.Is(n.Err, fs.ErrNotExist) && n.Lookup != nil:
		f.Severity = core.Blocker
		f = lookupMissing(n, f)
	case errors.Is(n.Err, fs.ErrNotExist):
		f.Severity = core.Blocker
		f.Summary = "does not exist"
		f.Detail = n.Path + " does not exist."
		if s := suggest(ctx, n); s != "" {
			f.Detail += "\nDid you mean " + s + "?"
		}
	case errors.Is(n.Err, syscall.ELOOP):
		f.Severity = core.Blocker
		f.Summary = "too many levels of symbolic links"
		f.Detail = fmt.Sprintf("Resolving the path followed more than 40 symbolic links when it reached\n%s, so there is probably a loop.", n.Path)
	case errors.Is(n.Err, fs.ErrPermission):
		f.Severity = core.Unknown
		f.Summary = "whycant cannot inspect this path"
		f.Detail = fmt.Sprintf("whycant is running as %s and is not allowed to look at %s,\nso it cannot tell what lies beyond it.",
			ctx.InvokerName, n.Path)
		f.Fixes = []core.Fix{{
			Description: "Run whycant as root to see the whole chain",
			Commands:    []string{fix.Command(true, ctx.Argv...)},
			Risk:        core.RiskLow,
		}}
	default:
		f.Severity = core.Unknown
		f.Summary = "cannot inspect"
		f.Detail = fmt.Sprintf("whycant could not inspect %s: %v.", n.Path, n.Err)
	}
	return f
}

// suggest returns up to three existing siblings whose names are close to the
// missing one, quoted as full paths.
func suggest(ctx *Context, n *core.Node) string {
	if ctx.Sys == nil || n.Dir == nil {
		return ""
	}
	names, err := ctx.Sys.ReadDirNames(n.Dir.Path)
	if err != nil {
		return ""
	}
	want := path.Base(n.Path)
	var out []string
	for _, name := range names {
		if similar(want, name) {
			out = append(out, fix.Quote(path.Join(n.Dir.Path, name)))
			if len(out) == 3 {
				break
			}
		}
	}
	return strings.Join(out, " or ")
}

// similar reports a case-insensitive match or a small typo.
func similar(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	limit := 1
	if len(a) >= 6 {
		limit = 2
	}
	return len(a) >= 3 && editDistance(strings.ToLower(a), strings.ToLower(b)) <= limit
}

func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

func targetType(ctx *Context, n *core.Node, f core.Finding) []core.Finding {
	fi := n.Info
	if typeOK(ctx.Action, fi) {
		switch {
		case ctx.Action == core.Read && fi.IsDir():
			f.Severity = core.Info
			f.Summary = "is a directory"
			f.Detail = fmt.Sprintf("%s is a directory. Reading a directory means listing its names;\nfor the full picture use: %s",
				n.Path, fix.Command(false, "whycant", "list", n.Path))
		case ctx.Action == core.Create:
			f.Severity = core.Info
			f.Summary = "already exists"
			f.Detail = fmt.Sprintf("%s already exists. Creating it would open the existing %s (or fail,\nwith O_EXCL); the check above covers adding entries to its directory.",
				n.Path, typeName(fi))
		default:
			return nil
		}
		return []core.Finding{f}
	}

	if ctx.AccessOnly {
		return nil // access(2) does not look at the file type
	}
	f.Severity = core.Blocker
	switch ctx.Action {
	case core.Traverse, core.List:
		f.Summary = "not a directory"
		verb := "entered"
		if ctx.Action == core.List {
			verb = "listed"
		}
		f.Detail = fmt.Sprintf("%s is a %s, not a directory, so it cannot be %s.", n.Path, typeName(fi), verb)
	case core.Write, core.Append:
		f.Summary = "is a directory"
		f.Detail = fmt.Sprintf("%s is a directory, which cannot be opened for writing. To check adding\na file inside it: %s",
			n.Path, fix.Command(false, "whycant", "create", path.Join(n.Path, "NAME")))
	case core.Exec:
		if fi.IsDir() {
			f.Summary = "is a directory"
			f.Detail = fmt.Sprintf("%s is a directory, which cannot be run. To check entering it:\n%s",
				n.Path, fix.Command(false, "whycant", "traverse", n.Path))
		} else {
			f.Summary = "not a regular file"
			f.Detail = fmt.Sprintf("%s is a %s, which cannot be run.", n.Path, typeName(fi))
		}
	}
	return []core.Finding{f}
}
