// Package checks holds one access check per file. Each check looks at a
// single node of the chain and reports findings; the engine decides the
// verdict.
package checks

import (
	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// Context is what every check can see.
type Context struct {
	Sys     sys.System
	Subject *core.Subject
	Action  core.Action
	// InvokerUID and InvokerName describe the user running whycant, which
	// decides whether fixes need sudo.
	InvokerUID  uint32
	InvokerName string
	// Argv is the whycant command line, for "re-run with sudo" fixes.
	Argv []string
}

// sudoFor reports whether the invoker needs sudo to change a file owned by owner.
func (c *Context) sudoFor(owner uint32) bool {
	return c.InvokerUID != 0 && c.InvokerUID != owner
}

// Check is one kind of access check.
type Check interface {
	Name() string
	Applies(ctx *Context, n *core.Node) bool
	Evaluate(ctx *Context, n *core.Node) []core.Finding
}

// Default returns the checks in the order the engine runs them.
func Default() []Check {
	return []Check{Path{}, DAC{}}
}

// inspectable reports whether n was lstatted and has a type that the action
// can work with, so permission checks are meaningful.
func inspectable(ctx *Context, n *core.Node) bool {
	if !n.Exists || n.Info.IsSymlink() {
		return false
	}
	if n.Role == core.RoleAncestor {
		return n.Info.IsDir()
	}
	return typeOK(ctx.Action, n.Info)
}

func typeOK(a core.Action, fi sys.FileInfo) bool {
	switch a {
	case core.Traverse, core.List:
		return fi.IsDir()
	case core.Write, core.Append:
		return !fi.IsDir()
	case core.Exec:
		return fi.IsRegular()
	}
	return true
}

func typeName(fi sys.FileInfo) string {
	switch fi.Type() {
	case sys.TypeDir:
		return "directory"
	case sys.TypeRegular:
		return "regular file"
	case sys.TypeSymlink:
		return "symbolic link"
	case sys.TypeChar:
		return "character device"
	case sys.TypeBlock:
		return "block device"
	case sys.TypeFIFO:
		return "named pipe"
	case sys.TypeSocket:
		return "socket"
	}
	return "file of unknown type"
}
