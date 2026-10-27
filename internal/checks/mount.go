package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// Mount checks mount options (ro, noexec, nosuid), FUSE access restrictions
// and filesystem types whose permissions are not what they seem.
type Mount struct{}

// Name implements Check.
func (Mount) Name() string { return "mount" }

// Applies implements Check.
func (Mount) Applies(_ *Context, n *core.Node) bool {
	return n.Exists && n.Mount != nil && !n.Info.IsSymlink()
}

// Evaluate implements Check.
func (Mount) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	m := n.Mount
	var out []core.Finding
	add := func(sev core.Severity, conf core.Confidence, summary, detail string, fixes ...core.Fix) {
		out = append(out, core.Finding{
			Check: "mount", NodePath: n.Path, Severity: sev, Confidence: conf,
			Summary: summary, Detail: detail, Fixes: fixes,
		})
	}
	sudo := ctx.InvokerUID != 0

	if strings.HasPrefix(m.FSType, "fuse") && n.Path == m.MountPoint && !m.Has("allow_other") {
		// fuse_allow_current_process(): without allow_other, the caller's
		// uid must be user_id and its gid group_id.
		owner, ok := m.Value("user_id")
		group, hasGroup := m.Value("group_id")
		if ok && (owner != strconv.FormatUint(uint64(ctx.Subject.UID), 10) ||
			hasGroup && group != strconv.FormatUint(uint64(ctx.Subject.GID), 10)) {
			uid, _ := strconv.ParseUint(owner, 10, 32)
			add(core.Blocker, core.Likely, "FUSE mount without allow_other",
				fmt.Sprintf("%s is a FUSE filesystem (%s) mounted by %s without allow_other,\nso only that user can use it. Not even root can.",
					m.MountPoint, m.FSType, ctx.userName(uint32(uid))),
				core.Fix{
					Description: "Have the owner remount it with -o allow_other",
					Risk:        core.RiskMedium,
					Note:        "other users also need user_allow_other in /etc/fuse.conf",
				})
		}
	}

	// inode_permission() only refuses writes on read-only mounts for
	// regular files, directories and symlinks; devices and FIFOs stay usable.
	if modifies(ctx, n) && m.ReadOnly() && !specialFile(n.Info) {
		bind := !hasOpt(m.SuperOptions, "ro")
		detail := fmt.Sprintf("%s is mounted read-only. Nothing there can be changed, not even by root.", m.MountPoint)
		if n.Path != m.MountPoint {
			detail = fmt.Sprintf("%s is on %s, which is mounted read-only. Nothing there can be\nchanged, not even by root.", n.Path, m.MountPoint)
		}
		remount := []string{"mount", "-o", "remount,rw", m.MountPoint}
		if bind {
			detail += "\nIt is a read-only bind mount; the filesystem underneath is writable elsewhere."
			remount = []string{"mount", "-o", "remount,rw,bind", m.MountPoint}
		}
		add(core.Blocker, core.Certain, "read-only mount", detail, core.Fix{
			Description: "Remount it read-write",
			Commands:    []string{fix.Command(sudo, remount...)},
			Risk:        core.RiskMedium,
			Note:        "first find out why it is read-only, e.g. filesystem errors in dmesg",
		})
	}

	if executes(ctx, n) && n.Info.IsRegular() {
		if m.Has("noexec") {
			add(core.Blocker, core.Certain, "noexec mount",
				fmt.Sprintf("%s is on %s, which is mounted noexec: files there cannot be run\ndirectly, not even by root. Passing a script to its interpreter still works\n(for example: sh %s).",
					n.Path, m.MountPoint, fix.Quote(n.Path)),
				core.Fix{
					Description: "Remount it with exec",
					Commands:    []string{fix.Command(sudo, "mount", "-o", "remount,exec", m.MountPoint)},
					Risk:        core.RiskMedium,
					Note:        "noexec is often set on purpose, e.g. for /tmp",
				})
		}
		if n.Info.Mode&(sys.ModeSetuid|sys.ModeSetgid) != 0 && m.Has("nosuid") {
			add(core.Info, core.Certain, "setuid/setgid bit is ignored here",
				fmt.Sprintf("%s is on %s, which is mounted nosuid, so its setuid/setgid bit has\nno effect: it will run with the caller's own privileges.", n.Path, m.MountPoint))
		}
	}

	if subjectNode(ctx, n) {
		switch {
		case isSyntheticFS(m.FSType):
			uid, _ := m.Value("uid")
			gid, _ := m.Value("gid")
			add(core.Warn, core.Certain, m.FSType+" has no real Unix permissions",
				fmt.Sprintf("%s is on a %s filesystem, which does not store owners or modes. The ones shown\ncome from mount options (uid=%s, gid=%s, umask/fmask/dmask), so chmod and chown\nwill not help.",
					n.Path, m.FSType, orNone(uid), orNone(gid)),
				core.Fix{
					Description: fmt.Sprintf("Mount it with uid=%d,gid=%d (or a wider umask) in /etc/fstab, then remount", ctx.Subject.UID, ctx.Subject.GID),
					Risk:        core.RiskMedium,
				})
		case isNetworkFS(m.FSType):
			detail := fmt.Sprintf("%s is on a %s filesystem. The server makes the final decision, so this\nlocal analysis may be wrong.", n.Path, m.FSType)
			if ctx.Subject.UID == 0 {
				detail += "\nNFS servers usually map root to nobody (root_squash), so root may have no special access."
			}
			add(core.Warn, core.Certain, "network filesystem: the server decides", detail)
		case m.FSType == "overlay":
			add(core.Pass, core.Certain, "on an overlay filesystem", "")
		}
	}
	return out
}

func specialFile(fi sys.FileInfo) bool {
	switch fi.Type() {
	case sys.TypeChar, sys.TypeBlock, sys.TypeFIFO, sys.TypeSocket:
		return true
	}
	return false
}

func hasOpt(opts []string, opt string) bool {
	for _, o := range opts {
		if o == opt {
			return true
		}
	}
	return false
}

func isSyntheticFS(t string) bool {
	switch t {
	case "vfat", "msdos", "exfat", "ntfs", "ntfs3", "fuseblk", "hfsplus", "iso9660", "udf":
		return true
	}
	return false
}

func isNetworkFS(t string) bool {
	switch t {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "ceph", "glusterfs", "fuse.sshfs":
		return true
	}
	return false
}

func orNone(s string) string {
	if s == "" {
		return "0 by default"
	}
	return s
}
