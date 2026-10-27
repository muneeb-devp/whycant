package checks

import (
	"fmt"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
)

// AppArmor looks for recent AppArmor denials for the path in the kernel log.
// AppArmor confines programs, not users, so it can deny a service what its
// user is allowed to do.
type AppArmor struct{}

// Name implements Check.
func (AppArmor) Name() string { return "apparmor" }

// Applies implements Check.
func (AppArmor) Applies(ctx *Context, n *core.Node) bool {
	return subjectNode(ctx, n) && ctx.Sys != nil && ctx.lsm().apparmor
}

// Evaluate implements Check.
func (AppArmor) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	f := core.Finding{Check: "apparmor", NodePath: n.Path, Confidence: core.Certain}
	lines, source, ok := ctx.logLines(
		[]string{"journalctl", "-k", "--since=-24h", "-o", "cat", "--no-pager"},
		[]string{"dmesg"},
	)
	if !ok {
		f.Severity = core.Pass
		f.Summary = "AppArmor is enabled; the kernel log could not be read"
		return []core.Finding{f}
	}

	needle := `name="` + n.Path + `"`
	var denials []string
	profiles := map[string]bool{}
	var order []string
	for _, line := range lines {
		if !strings.Contains(line, `apparmor="DENIED"`) || !strings.Contains(line, needle) {
			continue
		}
		denials = append(denials, "  "+trimLine(line))
		if p := field(line, "profile"); p != "" && !profiles[p] {
			profiles[p] = true
			order = append(order, p)
		}
	}
	if len(denials) == 0 {
		f.Severity = core.Pass
		f.Summary = "AppArmor logged no recent denials for this path"
		return []core.Finding{f}
	}

	f.Severity = core.Blocker
	f.Confidence = core.Likely
	f.Summary = "AppArmor denied access recently (profile " + strings.Join(order, ", ") + ")"
	f.Detail = fmt.Sprintf("AppArmor logged %d recent denial(s) for %s (from %s):\n%s\nAppArmor confines programs, not users: %s may be allowed by the permissions while\nthe program running under that profile is not.",
		len(denials), n.Path, source, strings.Join(lastN(denials, 3), "\n"), ctx.Subject.Who())
	f.Fixes = []core.Fix{{
		Description: "Review the denials and update the profile",
		Commands:    []string{fix.Command(ctx.InvokerUID != 0, "aa-logprof")},
		Risk:        core.RiskMedium,
		Note:        "or add a rule for " + n.Path + " to the profile in /etc/apparmor.d and reload it with apparmor_parser -r",
	}}
	return []core.Finding{f}
}

// field extracts key="value" from an audit line.
func field(line, key string) string {
	_, rest, ok := strings.Cut(line, key+`="`)
	if !ok {
		return ""
	}
	v, _, _ := strings.Cut(rest, `"`)
	return v
}
