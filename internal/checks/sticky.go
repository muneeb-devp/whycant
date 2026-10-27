package checks

import (
	"fmt"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// Sticky enforces the restricted-deletion rule of sticky directories such
// as /tmp: only the file's owner, the directory's owner or CAP_FOWNER may
// delete or rename an entry.
type Sticky struct{}

// Name implements Check.
func (Sticky) Name() string { return "sticky" }

// Applies implements Check.
func (Sticky) Applies(ctx *Context, n *core.Node) bool {
	return ctx.Action == core.Delete && n.Role == core.RoleTarget && n.Exists && n.Dir != nil &&
		n.Dir.Info.Mode&sys.ModeSticky != 0
}

// Evaluate implements Check.
func (Sticky) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	s, dir := ctx.Subject, n.Dir
	f := core.Finding{Check: "sticky", NodePath: n.Path, Confidence: core.Certain}
	switch {
	case s.UID == n.Info.UID:
		f.Severity, f.Summary = core.Pass, "sticky directory, but "+s.Who()+" owns the file"
	case s.UID == dir.Info.UID:
		f.Severity, f.Summary = core.Pass, "sticky directory, but "+s.Who()+" owns the directory"
	case s.Caps.Has(core.CapFowner):
		f.Severity, f.Summary = core.Pass, "sticky directory, but "+s.Who()+" has CAP_FOWNER"
	default:
		f.Severity = core.Blocker
		f.Summary = "sticky directory: only the owner may delete"
		f.Detail = fmt.Sprintf("%s has the sticky bit (the t in %s), so only the file's owner (%s),\nthe directory's owner (%s) or root may delete or rename entries in it,\neven though %s can write to the directory.",
			dir.Path, dir.Info.ModeString(), n.OwnerName, dir.OwnerName, s.Who())
		f.Fixes = []core.Fix{
			{Description: fmt.Sprintf("Ask %s, who owns the file, to delete it", n.OwnerName), Risk: core.RiskLow},
			{
				Description: "Delete it as root",
				Commands:    []string{fix.Command(ctx.InvokerUID != 0, "rm", "--", n.Path)},
				Risk:        core.RiskMedium,
			},
		}
	}
	return []core.Finding{f}
}
