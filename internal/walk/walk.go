// Package walk turns a path into the ordered chain of nodes the kernel
// visits, recording what each must grant.
package walk

import (
	"fmt"
	"path"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// Walk lstats every component of p from "/" down. Once a component cannot
// be inspected, or cannot contain further components (missing, not a
// directory, a symlink), the rest are returned unlstatted so the report can
// show them as not evaluated.
func Walk(s sys.System, action core.Action, p string) ([]*core.Node, error) {
	if !path.IsAbs(p) {
		wd, err := s.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolving relative path: %w", err)
		}
		p = path.Join(wd, p)
	}
	p = path.Clean(p)

	components := []string{"/"}
	if p != "/" {
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		for i := range parts {
			components = append(components, "/"+strings.Join(parts[:i+1], "/"))
		}
	}

	nodes := make([]*core.Node, len(components))
	stopped := false
	for i, c := range components {
		n := &core.Node{Path: c, Resolved: c, Role: core.RoleAncestor, Need: core.PermX}
		if i == len(components)-1 {
			n.Role = core.RoleTarget
			n.Need = TargetNeed(action)
		}
		nodes[i] = n
		if stopped {
			continue
		}
		fi, err := s.Lstat(c)
		if err != nil {
			n.Err = err
			stopped = true
			continue
		}
		n.Info, n.Exists = fi, true
		if n.Role == core.RoleAncestor && !fi.IsDir() {
			// Symlinked ancestors are followed from milestone 2; non-directory
			// ancestors end the walk.
			stopped = true
		}
	}
	return nodes, nil
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
