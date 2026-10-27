package checks

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
)

// SELinux reports the SELinux mode, compares the file's label with the
// policy default, and looks for recent AVC denials for the path. It does not
// evaluate policy itself.
type SELinux struct{}

// Name implements Check.
func (SELinux) Name() string { return "selinux" }

// Applies implements Check.
func (SELinux) Applies(ctx *Context, n *core.Node) bool {
	return n.Exists && subjectNode(ctx, n) && ctx.Sys != nil && ctx.lsm().selinux
}

// Evaluate implements Check.
func (SELinux) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	st := ctx.lsm()
	var out []core.Finding
	add := func(sev core.Severity, conf core.Confidence, summary, detail string, fixes ...core.Fix) {
		out = append(out, core.Finding{
			Check: "selinux", NodePath: n.Path, Severity: sev, Confidence: conf,
			Summary: summary, Detail: detail, Fixes: fixes,
		})
	}

	if st.enforce < 0 {
		add(core.Warn, core.Possible, "SELinux is active but its mode could not be read",
			"whycant could not read /sys/fs/selinux/enforce or run getenforce, so it cannot\ntell whether SELinux is enforcing. It may deny access that the permissions allow.")
		return out
	}
	mode := "enforcing"
	if st.enforce == 0 {
		mode = "permissive"
	}

	label := ""
	if b, err := ctx.Sys.Getxattr(n.Path, "security.selinux"); err == nil {
		label = strings.TrimRight(string(b), "\x00")
	}
	var restorecon *core.Fix
	mismatch := ""
	if label != "" {
		if out, err := ctx.Sys.Run("matchpathcon", "-n", n.Path); err == nil {
			expected := strings.TrimSpace(string(out))
			if expected != "" && seType(expected) != seType(label) {
				restorecon = &core.Fix{
					Description: "Restore the label the policy expects",
					Commands:    []string{fix.Command(ctx.InvokerUID != 0, "restorecon", "-v", n.Path)},
					Risk:        core.RiskLow,
				}
				mismatch = fmt.Sprintf("%s is labeled %s, but the policy expects %s.\nFiles moved (mv) from elsewhere keep their old label, which confined services are\noften not allowed to use.", n.Path, label, expected)
			}
		}
	}

	denials, source, readable := avcDenials(ctx, n)
	blocked := readable && len(denials) > 0 && st.enforce == 1
	if mismatch != "" && !blocked {
		add(core.Warn, core.Certain, "SELinux label differs from the policy default", mismatch, *restorecon)
	}
	switch {
	case !readable:
		add(core.Info, core.Certain, "SELinux is "+mode+"; the audit log could not be read",
			fmt.Sprintf("whycant could not read /var/log/audit/audit.log or the audit journal, so it cannot\nsee recent SELinux denials for %s. Run it with sudo to include them.", n.Path))
	case blocked:
		fixes := []core.Fix{}
		if restorecon != nil {
			fixes = append(fixes, *restorecon)
		}
		fixes = append(fixes, core.Fix{
			Description: "See why the policy denies it",
			Commands:    []string{fix.Command(ctx.InvokerUID != 0, "ausearch", "-m", "avc", "-ts", "recent", "-f", n.Path) + " | audit2why"},
			Risk:        core.RiskLow,
			Note:        "then fix the label, or adjust the policy with a boolean or an audit2allow module; do not disable SELinux",
		})
		detail := fmt.Sprintf("SELinux is enforcing and logged %d recent denial(s) for %s (from %s):\n%s",
			len(denials), n.Path, source, strings.Join(denials, "\n"))
		if mismatch != "" {
			detail += "\n" + mismatch
		}
		add(core.Blocker, core.Likely, "SELinux denied access recently", detail, fixes...)
	case len(denials) > 0:
		add(core.Info, core.Certain, "SELinux is permissive but logged denials",
			fmt.Sprintf("SELinux is permissive, so it only logs. These denials for %s would block access\nin enforcing mode:\n%s", n.Path, strings.Join(denials, "\n")))
	default:
		detail := fmt.Sprintf("SELinux is %s and logged no denials for %s in the last day.", mode, n.Path)
		if label != "" {
			detail = fmt.Sprintf("SELinux is %s; %s is labeled %s. No denials for it in the last day.", mode, n.Path, label)
		}
		add(core.Info, core.Certain, "SELinux is "+mode, detail)
	}
	return out
}

// avcDenials returns recent AVC denial lines that mention the node, by
// path, by name together with its inode number, or by inode alone.
func avcDenials(ctx *Context, n *core.Node) (matches []string, source string, readable bool) {
	lines, source, ok := ctx.logLines(
		[]string{"/var/log/audit/audit.log"},
		[]string{"journalctl", "_TRANSPORT=audit", "--since=-24h", "-o", "cat", "--no-pager"},
	)
	if !ok {
		return nil, "", false
	}
	ino := "ino=" + strconv.FormatUint(n.Info.Ino, 10)
	name := `name="` + path.Base(n.Path) + `"`
	full := `path="` + n.Path + `"`
	for _, line := range lines {
		if !strings.Contains(line, "avc:") || !strings.Contains(line, "denied") {
			continue
		}
		if strings.Contains(line, full) || hasToken(line, ino) && (strings.Contains(line, name) || !strings.Contains(line, "name=")) {
			matches = append(matches, "  "+trimLine(line))
		}
	}
	return lastN(matches, 3), source, true
}

// hasToken reports whether tok appears as a whole space-separated field.
func hasToken(line, tok string) bool {
	for _, f := range strings.Fields(line) {
		if f == tok {
			return true
		}
	}
	return false
}

// seType extracts the type from user:role:type:level.
func seType(ctx string) string {
	parts := strings.SplitN(ctx, ":", 4)
	if len(parts) < 3 {
		return ctx
	}
	return parts[2]
}
