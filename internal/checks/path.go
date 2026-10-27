package checks

import (
	"errors"
	"fmt"
	"io/fs"

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

	case n.Info.IsSymlink():
		f.Severity = core.Unknown
		f.Summary = "symbolic links are not followed yet"
		f.Detail = fmt.Sprintf("%s is a symbolic link to %s.\nwhycant does not follow symbolic links yet, so it cannot say what lies beyond it.",
			n.Path, n.Info.LinkTarget)

	case n.Role == core.RoleAncestor && !n.Info.IsDir():
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
	case errors.Is(n.Err, fs.ErrNotExist):
		f.Severity = core.Blocker
		f.Summary = "does not exist"
		f.Detail = n.Path + " does not exist."
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

func targetType(ctx *Context, n *core.Node, f core.Finding) []core.Finding {
	fi := n.Info
	if typeOK(ctx.Action, fi) {
		if ctx.Action == core.Read && fi.IsDir() {
			f.Severity = core.Info
			f.Summary = "is a directory"
			f.Detail = fmt.Sprintf("%s is a directory. Reading a directory means listing its names;\nfor the full picture use: %s",
				n.Path, fix.Command(false, "whycant", "list", n.Path))
			return []core.Finding{f}
		}
		return nil
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
		f.Detail = fmt.Sprintf("%s is a directory, which cannot be opened for writing.\nTo add a file inside it, ask about creating one instead.", n.Path)
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
