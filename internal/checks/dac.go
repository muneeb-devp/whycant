package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// DAC evaluates the classic owner/group/other mode bits, with the kernel's
// exclusive class selection and root's capability overrides.
type DAC struct{}

// Name implements Check.
func (DAC) Name() string { return "dac" }

// Applies implements Check.
func (DAC) Applies(ctx *Context, n *core.Node) bool { return inspectable(ctx, n) }

type class int

const (
	classOwner class = iota
	classGroup
	classOther
)

func (c class) String() string {
	return [...]string{"owner", "group", "other"}[c]
}

// classOf picks the one permission class the kernel uses: owner bits for the
// owner, else group bits for group members, else other bits. It never falls
// through to a more permissive class.
func classOf(s *core.Subject, fi sys.FileInfo) (class, core.Perm) {
	switch {
	case s.UID == fi.UID:
		return classOwner, permOf(fi, classOwner)
	case s.InGroup(fi.GID):
		return classGroup, permOf(fi, classGroup)
	}
	return classOther, permOf(fi, classOther)
}

func permOf(fi sys.FileInfo, c class) core.Perm {
	return core.Perm(fi.Mode >> (3 * (2 - uint(c))) & 7)
}

// Evaluate implements Check.
func (DAC) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	s, fi := ctx.Subject, n.Info
	cls, bits := classOf(s, fi)

	granted := bits
	override := false
	switch {
	case s.Caps.Has(core.CapDACOverride):
		// Read and write always pass; execute needs an x bit somewhere on
		// non-directories.
		granted |= core.PermR | core.PermW
		if fi.IsDir() || fi.Perm()&0o111 != 0 {
			granted |= core.PermX
		}
		override = true
	case s.Caps.Has(core.CapDACReadSearch):
		granted |= core.PermR
		if fi.IsDir() {
			granted |= core.PermX
		}
		override = true
	}

	missing := n.Need &^ granted
	f := core.Finding{Check: "dac", NodePath: n.Path, Confidence: core.Certain}
	if missing == 0 {
		f.Severity = core.Pass
		if override && bits&n.Need != n.Need {
			f.Summary = s.Who() + " bypasses the permission bits"
		} else {
			f.Summary = fmt.Sprintf("%s permissions %s include %s", cls, bits, n.Need.Short())
		}
		out := []core.Finding{f}
		if w, ok := listWithoutX(ctx, n, granted); ok {
			out = append(out, w)
		}
		return out
	}

	f.Severity = core.Blocker
	if override {
		// Only exec of a file with no x bit at all gets here.
		f.Summary = "no execute bit is set"
		f.Detail = fmt.Sprintf("%s bypasses most permission checks, but the kernel only runs a file\nif at least one execute bit is set, and %s has mode %s.",
			s.Who(), n.Path, fi.ModeString())
		f.Fixes = []core.Fix{{
			Description: "Make the file executable for its owner",
			Commands:    []string{fix.Command(ctx.sudoFor(fi.UID), "chmod", "u+x", n.Path)},
			Risk:        core.RiskLow,
		}}
		return []core.Finding{f}
	}

	f.Summary = fmt.Sprintf("%s class has no %s permission", cls, permWords(missing))
	f.Detail = explain(ctx, n, cls, bits)
	f.Fixes = dacFixes(ctx, n, cls, missing)
	return []core.Finding{f}
}

func explain(ctx *Context, n *core.Node, cls class, bits core.Perm) string {
	s, fi := ctx.Subject, n.Info
	need := needSentence(ctx, n)
	group := permOf(fi, classGroup)
	other := permOf(fi, classOther)
	switch cls {
	case classOwner:
		text := fmt.Sprintf("%s owns %s, so only the owner permissions apply: %s.\n%s", s.Who(), n.Path, bits, need)
		if (group|other)&n.Need == n.Need {
			text += fmt.Sprintf("\nThe group (%s) and other (%s) permissions would allow it, but they never\napply to the owner: owner bits are used on their own.", group, other)
		}
		return text
	case classGroup:
		text := fmt.Sprintf("%s is not the owner (%s) but is in group %q,\nso the group permissions apply: %s. %s", s.Who(), n.OwnerName, n.GroupName, bits, need)
		if other&n.Need == n.Need {
			text += fmt.Sprintf("\nThe other permissions (%s) would allow it, but they never apply to members\nof the file's group.", other)
		}
		return text
	}
	return fmt.Sprintf("%s is not the owner (%s) and is not in group %q,\nso the \"other\" permissions apply: %s. %s", s.Who(), n.OwnerName, n.GroupName, bits, need)
}

func dacFixes(ctx *Context, n *core.Node, cls class, missing core.Perm) []core.Fix {
	s, fi := ctx.Subject, n.Info
	if cls == classOwner {
		return []core.Fix{{
			Description: fmt.Sprintf("Give the owner (%s) the missing %s permission", s.Who(), missing.Short()),
			Commands:    []string{fix.Command(ctx.sudoFor(fi.UID), "chmod", "u+"+missing.Short(), n.Path)},
			Risk:        core.RiskLow,
		}}
	}

	aclUser := s.Name
	if aclUser == "" {
		aclUser = strconv.FormatUint(uint64(s.UID), 10)
	}
	fixes := []core.Fix{{
		Description: fmt.Sprintf("Grant %s only to %s via ACL", accessWord(ctx, n), s.Who()),
		Commands:    []string{fix.Command(ctx.sudoFor(fi.UID), "setfacl", "-m", "u:"+aclUser+":"+n.Need.Short(), n.Path)},
		Risk:        core.RiskLow,
	}}

	switch {
	case cls == classGroup:
		fixes = append(fixes, core.Fix{
			Description: fmt.Sprintf("Give group %q the missing %s permission", n.GroupName, missing.Short()),
			Commands:    []string{fix.Command(ctx.sudoFor(fi.UID), "chmod", "g+"+missing.Short(), n.Path)},
			Risk:        core.RiskMedium,
			Note:        fmt.Sprintf("this affects every member of %s", n.GroupName),
		})
	case permOf(fi, classGroup)&n.Need == n.Need && s.Name != "":
		note := "restart the service afterwards"
		if s.Current {
			note = "log out and back in afterwards"
		}
		fixes = append(fixes, core.Fix{
			Description: fmt.Sprintf("Add %s to the %s group", s.Name, n.GroupName),
			Commands:    []string{fix.Command(ctx.InvokerUID != 0, "usermod", "-aG", n.GroupName, s.Name)},
			Risk:        core.RiskMedium,
			Note:        note,
		})
	}
	return fixes
}

// listWithoutX explains the directory with r but not x case.
func listWithoutX(ctx *Context, n *core.Node, granted core.Perm) (core.Finding, bool) {
	if ctx.Action != core.List || n.Role != core.RoleTarget || granted&core.PermX != 0 {
		return core.Finding{}, false
	}
	return core.Finding{
		Check:      "dac",
		NodePath:   n.Path,
		Severity:   core.Warn,
		Confidence: core.Certain,
		Summary:    "can list names but not open or inspect entries",
		Detail: fmt.Sprintf("%s has r but not x on %s, so it can list the names inside\nbut cannot open the entries or see their details (ls -l shows ?????).",
			ctx.Subject.Who(), n.Path),
	}, true
}

func needSentence(ctx *Context, n *core.Node) string {
	if n.Role == core.RoleAncestor || ctx.Action == core.Traverse {
		return "Entering a directory needs x."
	}
	switch ctx.Action {
	case core.Read:
		if n.Info.IsDir() {
			return "Reading a directory needs r."
		}
		return "Reading a file needs r."
	case core.Write:
		return "Writing to a file needs w."
	case core.Append:
		return "Appending to a file needs w."
	case core.Exec:
		return "Running a file needs x."
	case core.List:
		return "Listing a directory needs r."
	}
	return ""
}

func accessWord(ctx *Context, n *core.Node) string {
	if n.Role == core.RoleAncestor || ctx.Action == core.Traverse {
		return "traverse"
	}
	switch ctx.Action {
	case core.Read:
		return "read access"
	case core.Write, core.Append:
		return "write access"
	case core.Exec:
		return "execute access"
	case core.List:
		return "list access"
	}
	return "access"
}

func permWords(p core.Perm) string {
	var words []string
	if p&core.PermR != 0 {
		words = append(words, "read")
	}
	if p&core.PermW != 0 {
		words = append(words, "write")
	}
	if p&core.PermX != 0 {
		words = append(words, "execute")
	}
	return strings.Join(words, " or ")
}
