package checks

import (
	"fmt"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// Protected implements the fs.protected_symlinks, protected_regular and
// protected_fifos sysctls, which guard sticky shared directories such as
// /tmp. They apply to root too.
type Protected struct{}

// Name implements Check.
func (Protected) Name() string { return "protected" }

// Applies implements Check.
func (Protected) Applies(ctx *Context, n *core.Node) bool {
	if n.Dir == nil || !n.Exists || n.Dir.Info.Mode&sys.ModeSticky == 0 {
		return false
	}
	return n.Role == core.RoleSymlink ||
		(ctx.Action == core.Create && n.Role == core.RoleTarget)
}

// Evaluate implements Check.
func (Protected) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	if n.Role == core.RoleSymlink {
		return protectedSymlink(ctx, n)
	}
	return protectedCreate(ctx, n)
}

// protectedSymlink mirrors may_follow_link(): in a sticky world-writable
// directory, a symlink is only followed by its owner, or when the directory
// owner also owns the link.
func protectedSymlink(ctx *Context, n *core.Node) []core.Finding {
	dir, s := n.Dir, ctx.Subject
	if dir.Info.Mode&0o002 == 0 || s.UID == n.Info.UID || dir.Info.UID == n.Info.UID {
		return nil
	}
	level, known := ctx.sysctl("fs.protected_symlinks")
	if known && level == 0 {
		return nil
	}
	f := core.Finding{
		Check: "protected", NodePath: n.Path, Severity: core.Blocker, Confidence: core.Certain,
		Summary: "fs.protected_symlinks refuses to follow this link",
		Detail: fmt.Sprintf("%s is a symbolic link in %s, a sticky world-writable directory.\nWith fs.protected_symlinks on, the kernel only follows such a link for its owner (%s)\nor when the directory's owner (%s) owns it. This applies to root too.",
			n.Path, dir.Path, n.OwnerName, dir.OwnerName),
		Fixes: []core.Fix{
			{Description: "Use the link's target directly: " + fix.Quote(n.Resolved), Risk: core.RiskLow},
			{
				Description: fmt.Sprintf("Make %s the owner of the link", s.Who()),
				Commands:    []string{fix.Command(ctx.InvokerUID != 0, "chown", "-h", s.Who(), n.Path)},
				Risk:        core.RiskMedium,
			},
		},
	}
	if !known {
		f.Confidence = core.Likely
		f.Detail += "\n(whycant could not read the sysctl; it is on by default on most distributions.)"
	}
	return []core.Finding{f}
}

// protectedCreate mirrors may_create_in_sticky(): opening an existing file
// with O_CREAT in a sticky directory is refused when neither the opener nor
// the directory owner owns it.
func protectedCreate(ctx *Context, n *core.Node) []core.Finding {
	dir, s := n.Dir, ctx.Subject
	if n.Info.IsDir() || dir.Info.UID == n.Info.UID || s.UID == n.Info.UID {
		return nil
	}
	var name string
	switch {
	case n.Info.IsRegular():
		name = "fs.protected_regular"
	case n.Info.Type() == sys.TypeFIFO:
		name = "fs.protected_fifos"
	default:
		// Devices and sockets get no sysctl exemption in
		// may_create_in_sticky(); world-writable sticky dirs refuse them.
		// Older kernels differ, hence "likely".
		if dir.Info.Mode&0o002 == 0 {
			return nil
		}
		return []core.Finding{{
			Check: "protected", NodePath: n.Path, Severity: core.Blocker, Confidence: core.Likely,
			Summary: "opening another user's " + typeName(n.Info) + " for creating in a sticky directory",
			Detail: fmt.Sprintf("%s already exists in the sticky world-writable directory %s and belongs to %s.\nThe kernel refuses O_CREAT opens of such files unless you or the directory's owner own them.",
				n.Path, dir.Path, n.OwnerName),
		}}
	}
	level, known := ctx.sysctl(name)
	if !known {
		level = 1 // systemd's default
	}
	worldWritable := dir.Info.Mode&0o002 != 0
	groupWritable := dir.Info.Mode&0o020 != 0
	if level == 0 || (!worldWritable && (level < 2 || !groupWritable)) {
		return nil
	}
	f := core.Finding{
		Check: "protected", NodePath: n.Path, Severity: core.Blocker, Confidence: core.Certain,
		Summary: name + " refuses to open this existing file for creating",
		Detail: fmt.Sprintf("%s already exists in the sticky shared directory %s and belongs to %s.\nWith %s on, opening it with O_CREAT (as shells and most programs do)\nfails unless you or the directory's owner own it. This applies to root too.",
			n.Path, dir.Path, n.OwnerName, name),
		Fixes: []core.Fix{{Description: "Use a different file name, or ask " + n.OwnerName + " to remove the file", Risk: core.RiskLow}},
	}
	if !known {
		f.Confidence = core.Likely
	}
	return []core.Finding{f}
}
