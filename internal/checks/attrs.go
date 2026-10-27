package checks

import (
	"fmt"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// Attrs checks the immutable (i) and append-only (a) inode flags, which
// block changes even for root.
type Attrs struct{}

// Name implements Check.
func (Attrs) Name() string { return "attrs" }

// Applies implements Check.
func (Attrs) Applies(ctx *Context, n *core.Node) bool {
	if !n.Exists || (!n.Info.IsRegular() && !n.Info.IsDir()) {
		return false
	}
	return modifies(ctx, n) || (n.Role == core.RoleTarget && ctx.Action == core.Delete)
}

// Evaluate implements Check.
func (Attrs) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	f := core.Finding{Check: "attrs", NodePath: n.Path, Confidence: core.Certain}
	if !n.FlagsKnown {
		f.Severity = core.Pass
		f.Summary = "file attributes not checked (whycant could not read them)"
		return []core.Finding{f}
	}
	immutable := n.Flags&sys.FlagImmutable != 0
	appendOnly := n.Flags&sys.FlagAppendOnly != 0
	a := ctx.Action

	switch {
	case n.Role == core.RoleTarget && immutable && (a == core.Write || a == core.Append || a == core.Delete):
		f.Summary = "file is immutable (chattr +i)"
		f.Detail = fmt.Sprintf("%s has the immutable attribute: it cannot be changed, renamed or deleted,\nnot even by root.", n.Path)
		f.Fixes = []core.Fix{chattrFix(ctx, "-i", n.Path)}
	case n.Role == core.RoleTarget && appendOnly && a == core.Write && !ctx.AccessOnly:
		f.Summary = "file is append-only (chattr +a)"
		f.Detail = fmt.Sprintf("%s has the append-only attribute: it can only be opened for appending,\nso normal writes fail, even for root. Appending still works; to check that:\n%s",
			n.Path, fix.Command(false, "whycant", "append", n.Path))
		f.Fixes = []core.Fix{chattrFix(ctx, "-a", n.Path)}
	case n.Role == core.RoleTarget && appendOnly && a == core.Delete:
		f.Summary = "file is append-only (chattr +a)"
		f.Detail = fmt.Sprintf("%s has the append-only attribute, so it cannot be deleted or renamed,\nnot even by root.", n.Path)
		f.Fixes = []core.Fix{chattrFix(ctx, "-a", n.Path)}
	case n.Role == core.RoleParent && immutable:
		f.Summary = "directory is immutable (chattr +i)"
		f.Detail = fmt.Sprintf("%s has the immutable attribute: no entries can be created, deleted or\nrenamed in it, not even by root.", n.Path)
		f.Fixes = []core.Fix{chattrFix(ctx, "-i", n.Path)}
	case n.Role == core.RoleParent && appendOnly && a == core.Delete:
		f.Summary = "directory is append-only (chattr +a)"
		f.Detail = fmt.Sprintf("%s has the append-only attribute: entries can be added to it but not\nremoved or renamed, not even by root.", n.Path)
		f.Fixes = []core.Fix{chattrFix(ctx, "-a", n.Path)}
	default:
		f.Severity = core.Pass
		f.Summary = "no immutable or append-only attribute"
		return []core.Finding{f}
	}
	f.Severity = core.Blocker
	return []core.Finding{f}
}

func chattrFix(ctx *Context, flag, path string) core.Fix {
	return core.Fix{
		Description: "Remove the attribute",
		Commands:    []string{fix.Command(ctx.InvokerUID != 0, "chattr", flag, path)},
		Risk:        core.RiskMedium,
		Note:        "someone set this on purpose; find out why first",
	}
}
