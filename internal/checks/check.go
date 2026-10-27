// Package checks holds one access check per file. Each check looks at a
// single node of the chain and reports findings; the engine decides the
// verdict.
package checks

import (
	"strconv"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// Namer turns ids into names; identity.Resolver implements it.
type Namer interface {
	UserName(uid uint32) string
	GroupName(gid uint32) string
}

// Context is what every check can see.
type Context struct {
	Sys     sys.System
	Subject *core.Subject
	Action  core.Action
	Names   Namer // optional
	// InvokerUID and InvokerName describe the user running whycant, which
	// decides whether fixes need sudo.
	InvokerUID  uint32
	InvokerName string
	// Argv is the whycant command line, for "re-run with sudo" fixes.
	Argv []string

	sysctls map[string]sysctl
}

type sysctl struct {
	value int
	ok    bool
}

// sudoFor reports whether the invoker needs sudo to change a file owned by owner.
func (c *Context) sudoFor(owner uint32) bool {
	return c.InvokerUID != 0 && c.InvokerUID != owner
}

func (c *Context) userName(uid uint32) string {
	if c.Names != nil {
		return c.Names.UserName(uid)
	}
	return strconv.FormatUint(uint64(uid), 10)
}

func (c *Context) groupName(gid uint32) string {
	if c.Names != nil {
		return c.Names.GroupName(gid)
	}
	return strconv.FormatUint(uint64(gid), 10)
}

// sysctl reads an integer from /proc/sys/<name with dots as slashes>.
func (c *Context) sysctl(name string) (int, bool) {
	if v, ok := c.sysctls[name]; ok {
		return v.value, v.ok
	}
	var v sysctl
	if c.Sys != nil {
		if b, err := c.Sys.ReadFile("/proc/sys/" + strings.ReplaceAll(name, ".", "/")); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				v = sysctl{n, true}
			}
		}
	}
	if c.sysctls == nil {
		c.sysctls = map[string]sysctl{}
	}
	c.sysctls[name] = v
	return v.value, v.ok
}

// Check is one kind of access check.
type Check interface {
	Name() string
	Applies(ctx *Context, n *core.Node) bool
	Evaluate(ctx *Context, n *core.Node) []core.Finding
}

// Default returns the checks in the order the engine runs them: what blocks
// even root comes first, then permissions, then the subtler rules.
func Default() []Check {
	return []Check{Path{}, Mount{}, Attrs{}, Protected{}, DAC{}, Sticky{}, DefaultACL{}}
}

// inspectable reports whether n was lstatted and has a type that the action
// can work with, so permission checks are meaningful.
func inspectable(ctx *Context, n *core.Node) bool {
	if !n.Exists || n.Info.IsSymlink() || n.Err != nil {
		return false
	}
	switch n.Role {
	case core.RoleAncestor, core.RoleParent:
		return n.Info.IsDir()
	case core.RoleInterpreter, core.RoleLoader:
		return n.Info.IsRegular()
	}
	return typeOK(ctx.Action, n.Info)
}

// modifies reports whether n is where the action changes something: the
// target of write/append, or the parent of create/delete.
func modifies(ctx *Context, n *core.Node) bool {
	switch n.Role {
	case core.RoleTarget:
		return ctx.Action == core.Write || ctx.Action == core.Append
	case core.RoleParent:
		return ctx.Action == core.Create || ctx.Action == core.Delete
	}
	return false
}

// subjectNode reports whether n is the node a filesystem-level note should
// be attached to: the target, or the parent when the target is being created.
func subjectNode(ctx *Context, n *core.Node) bool {
	if ctx.Action == core.Create {
		return n.Role == core.RoleParent
	}
	return n.Role == core.RoleTarget
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
