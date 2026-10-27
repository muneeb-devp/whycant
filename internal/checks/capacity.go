package checks

import (
	"fmt"

	"github.com/muneeb-devp/whycant/internal/core"
)

// Capacity warns about full filesystems, which make writes fail with "No
// space left on device" rather than a permission error.
//
// TODO: disk quotas (quotactl) are out of scope for v1.
type Capacity struct{}

// Name implements Check.
func (Capacity) Name() string { return "capacity" }

// Applies implements Check.
func (Capacity) Applies(ctx *Context, n *core.Node) bool {
	return n.Exists && modifies(ctx, n) && ctx.Sys != nil
}

// Evaluate implements Check.
func (Capacity) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	st, err := ctx.Sys.Statfs(n.Path)
	if err != nil || st.Blocks == 0 {
		return nil
	}
	var out []core.Finding
	warn := func(summary, detail string) {
		out = append(out, core.Finding{
			Check: "capacity", NodePath: n.Path, Severity: core.Warn, Confidence: core.Certain,
			Summary: summary, Detail: detail,
		})
	}
	where := n.Path
	if n.Mount != nil {
		where = n.Mount.MountPoint
	}

	avail := st.Bavail
	if ctx.Subject.UID == 0 {
		avail = st.Bfree // root may use the reserved blocks
	}
	switch {
	case avail == 0:
		warn("filesystem is full", fmt.Sprintf("The filesystem holding %s has no free space left for %s, so writes will fail\nwith \"No space left on device\" whatever the permissions.", where, ctx.Subject.Who()))
	case avail*100 < st.Blocks:
		warn("filesystem is almost full", fmt.Sprintf("The filesystem holding %s has less than 1%% free space (%s left).", where, humanBytes(avail*uint64(max(st.Bsize, 0)))))
	}
	if ctx.Action == core.Create && st.Files > 0 {
		switch {
		case st.Ffree == 0:
			warn("no free inodes", fmt.Sprintf("The filesystem holding %s has no free inodes, so new files cannot be created\n(\"No space left on device\") even though there may be free space.", where))
		case st.Ffree*100 < st.Files:
			warn("almost out of inodes", fmt.Sprintf("The filesystem holding %s has less than 1%% of its inodes free.", where))
		}
	}
	return out
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
