package checks

import (
	"fmt"

	"github.com/muneeb-devp/whycant/internal/core"
)

// DefaultACL notes when a parent directory's default ACL will shape the
// permissions of a newly created entry. Access ACLs are evaluated by DAC.
type DefaultACL struct{}

// Name implements Check.
func (DefaultACL) Name() string { return "acl" }

// Applies implements Check.
func (DefaultACL) Applies(ctx *Context, n *core.Node) bool {
	return ctx.Action == core.Create && n.Role == core.RoleParent && n.DefaultACL != nil
}

// Evaluate implements Check.
func (DefaultACL) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	return []core.Finding{{
		Check: "acl", NodePath: n.Path, Severity: core.Info, Confidence: core.Certain,
		Summary: "new entries inherit a default ACL",
		Detail: fmt.Sprintf("%s has a default ACL, so a new entry starts with these permissions\n(limited by the mode the program asks for) instead of using the umask:\n%s",
			n.Path, n.DefaultACL.Format(ctx.userName, ctx.groupName)),
	}}
}
