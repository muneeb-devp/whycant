// Package walk turns a path into the ordered chain of nodes the kernel
// visits, recording what each must grant, and loads what the checks need
// about each node (ACLs, inode flags, mount).
package walk

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"syscall"

	"github.com/muneeb-devp/whycant/internal/acl"
	"github.com/muneeb-devp/whycant/internal/binfmt"
	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/mount"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// MaxSymlinks is the kernel's limit on symlinks followed in one lookup.
const MaxSymlinks = 40

// Walk resolves p component by component, as path lookup in the kernel
// does. Symlinks are followed (except a final one for delete, which acts on
// the link itself) and the components of their targets join the chain, so
// every directory reached through a link is checked for traverse too.
//
// Once a component cannot be inspected or cannot contain further components,
// the remaining ones are returned as unlstatted placeholders.
func Walk(s sys.System, action core.Action, p string) ([]*core.Node, error) {
	p, err := Abs(s, p)
	if err != nil {
		return nil, err
	}

	w := &walker{sys: s, action: action, byPath: map[string]*core.Node{}}
	w.mounts = loadMounts(s)
	w.run(p)
	for _, n := range w.nodes {
		w.enrich(n)
	}
	return w.nodes, nil
}

// Abs makes p absolute against the working directory. It does not clean
// the path: ".." must be resolved physically, after symlinks, as the kernel
// does, and a trailing slash means the target must be a directory.
func Abs(s sys.System, p string) (string, error) {
	if !path.IsAbs(p) {
		wd, err := s.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolving relative path: %w", err)
		}
		p = strings.TrimSuffix(wd, "/") + "/" + p
	}
	return p, nil
}

// loadMounts returns the mount table, or nil when it cannot be read.
func loadMounts(s sys.System) mount.Table {
	data, err := s.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	t, err := mount.Parse(data)
	if err != nil {
		return nil
	}
	return t
}

type walker struct {
	sys    sys.System
	action core.Action
	mounts mount.Table
	nodes  []*core.Node
	byPath map[string]*core.Node
}

func (w *walker) node(p string, dir *core.Node) (*core.Node, bool) {
	if n, ok := w.byPath[p]; ok {
		return n, false
	}
	n := &core.Node{Path: p, Resolved: p, Role: core.RoleAncestor, Need: core.PermX, Dir: dir}
	w.byPath[p] = n
	w.nodes = append(w.nodes, n)
	return n, true
}

func (w *walker) run(p string) {
	root, _ := w.node("/", nil)
	fi, err := w.sys.Lstat("/")
	if err != nil {
		root.Err = err
		return
	}
	root.Info, root.Exists = fi, true

	queue := split(p)
	if len(queue) == 0 {
		w.markTarget(root)
		return
	}

	cur := root
	links := 0
	stopped := false
	var last *core.Node
	for len(queue) > 0 {
		comp := queue[0]
		queue = queue[1:]
		final := len(queue) == 0

		if !stopped {
			switch comp {
			case ".":
				if final {
					last = cur
				}
				continue
			case "..":
				if parent, ok := w.byPath[path.Dir(cur.Path)]; ok {
					cur = parent
				}
				if final {
					last = cur
				}
				continue
			}
		}

		n, _ := w.node(path.Join(cur.Path, comp), cur)
		last = n
		if stopped {
			cur = n // placeholders nest under each other
			continue
		}
		fi, err := w.sys.Lstat(n.Path)
		if err != nil {
			n.Err = err
			stopped = true
			cur = n
			continue
		}
		n.Info, n.Exists = fi, true

		if fi.IsSymlink() && (!final || w.action != core.Delete) {
			links++
			n.Role, n.Need = core.RoleSymlink, 0
			if links > MaxSymlinks {
				n.Err = &fs.PathError{Op: "lookup", Path: n.Path, Err: syscall.ELOOP}
				stopped = true
				continue
			}
			target := fi.LinkTarget
			base := cur
			if path.IsAbs(target) {
				base = root
			}
			n.Resolved = path.Join(base.Path, target)
			cur = base
			queue = append(split(target), queue...)
			if len(queue) == 0 { // a link to "/" or "."
				last = cur
			}
			continue
		}
		if !final {
			stopped = !fi.IsDir()
			cur = n
		}
	}
	w.markTarget(last)

	// "dir/" and "dir/." require a directory, like O_DIRECTORY lookups.
	if last != nil && last.Exists && last.Err == nil && !last.Info.IsDir() && last.Role != core.RoleSymlink &&
		len(p) > 1 && (strings.HasSuffix(p, "/") || strings.HasSuffix(p, "/.")) {
		last.Err = &fs.PathError{Op: "lookup", Path: last.Path, Err: syscall.ENOTDIR}
	}
}

// markTarget sets the final node's role, and for create and delete makes
// the directory that holds it a parent that needs w and x.
func (w *walker) markTarget(n *core.Node) {
	if n == nil {
		return
	}
	n.Role = core.RoleTarget
	n.Need = TargetNeed(w.action)
	if w.action == core.Create || w.action == core.Delete {
		if n.Dir != nil {
			n.Dir.Role = core.RoleParent
			n.Dir.Need = core.PermW | core.PermX
		}
	}
	// The target must come last in the chain even when a link resolved it
	// to a node visited earlier.
	for i, m := range w.nodes {
		if m == n && i != len(w.nodes)-1 {
			w.nodes = append(append(w.nodes[:i:i], w.nodes[i+1:]...), n)
			break
		}
	}
}

func (w *walker) enrich(n *core.Node) {
	if !n.Exists || n.Info.IsSymlink() {
		return
	}
	n.Mount = w.mounts.Lookup(n.Path)
	if b, err := w.sys.Getxattr(n.Path, acl.XattrAccess); err == nil {
		if a, err := acl.Parse(b); err == nil && a.Extended() {
			n.ACL = a
		}
	}
	if n.Info.IsDir() && n.Role == core.RoleParent {
		if b, err := w.sys.Getxattr(n.Path, acl.XattrDefault); err == nil {
			if a, err := acl.Parse(b); err == nil {
				n.DefaultACL = a
			}
		}
	}
	if n.Info.IsDir() || n.Info.IsRegular() {
		if flags, err := w.sys.InodeFlags(n.Path); err == nil {
			n.Flags, n.FlagsKnown = flags, true
		} else {
			n.FlagsErr = err
		}
	}
	if w.action == core.Exec && n.Role == core.RoleTarget && n.Info.IsRegular() {
		n.Exec = ReadExec(w.sys, n.Path)
		if n.Exec.Kind == core.ExecScript {
			// The interpreter reopens the script by name, as the caller.
			n.Need |= core.PermR
		}
	}
}

// ReadExec identifies a file's executable format from its first bytes.
func ReadExec(s sys.System, p string) *core.ExecInfo {
	head, err := s.ReadHead(p, binfmt.HeadSize)
	if err != nil {
		return &core.ExecInfo{Kind: core.ExecUnreadable, Err: err}
	}
	if sb, ok := binfmt.ParseShebang(head); ok {
		return &core.ExecInfo{Kind: core.ExecScript, Shebang: sb}
	}
	if !binfmt.IsELF(head) {
		return &core.ExecInfo{Kind: core.ExecUnknownFormat}
	}
	e, err := binfmt.ParseELF(head)
	var more *binfmt.NeedMoreError
	if errors.As(err, &more) && more.Size <= 1<<20 {
		if head, err = s.ReadHead(p, more.Size); err == nil {
			e, err = binfmt.ParseELF(head)
		}
	}
	return &core.ExecInfo{Kind: core.ExecELF, ELF: e, Err: err}
}

func split(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// TargetNeed is what the final component must grant for action.
func TargetNeed(action core.Action) core.Perm {
	switch action {
	case core.Read, core.List:
		return core.PermR
	case core.Write, core.Append:
		return core.PermW
	case core.Exec, core.Traverse:
		return core.PermX
	}
	return 0
}
