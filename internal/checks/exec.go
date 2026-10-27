package checks

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/muneeb-devp/whycant/internal/binfmt"
	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
)

// Exec looks past permissions at why execve could still fail: unreadable
// scripts, broken #! lines, binaries for another architecture and unknown
// formats. Missing interpreters and loaders are found by the engine, which
// walks them as part of the chain.
type Exec struct{}

// Name implements Check.
func (Exec) Name() string { return "exec" }

// Applies implements Check.
func (Exec) Applies(ctx *Context, n *core.Node) bool {
	return ctx.Action == core.Exec && n.Exec != nil && n.Exists &&
		(n.Role == core.RoleTarget || n.Role == core.RoleInterpreter || n.Role == core.RoleLoader)
}

// Evaluate implements Check.
func (Exec) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	x := n.Exec
	f := core.Finding{Check: "exec", NodePath: n.Path, Confidence: core.Certain}
	switch x.Kind {
	case core.ExecUnreadable:
		if ctx.Subject.UID == ctx.InvokerUID || ctx.InvokerUID == 0 {
			// The subject cannot read it either; DAC explains that for scripts.
			return nil
		}
		f.Severity = core.Unknown
		f.Summary = "whycant cannot read the file to see what kind of program it is"
		f.Detail = fmt.Sprintf("whycant is running as %s and cannot read %s, so it cannot tell\nwhether it is a script (which also needs r) or a binary.", ctx.InvokerName, n.Path)
		f.Fixes = []core.Fix{{
			Description: "Run whycant as root to see the whole chain",
			Commands:    []string{fix.Command(true, ctx.Argv...)},
			Risk:        core.RiskLow,
		}}

	case core.ExecScript:
		sb := x.Shebang
		switch {
		case sb.CRLF:
			f.Severity = core.Blocker
			f.Summary = "script has Windows (CRLF) line endings"
			bad := sb.Interpreter
			if sb.Arg != "" {
				bad = sb.Arg
			}
			f.Detail = fmt.Sprintf("The #! line of %s ends with a carriage return (Windows line endings), so\nthe kernel looks for %s and fails with \"bad interpreter: No such file or directory\".",
				n.Path, strconv.Quote(bad))
			f.Fixes = []core.Fix{
				{
					Description: "Convert the file to Unix line endings",
					Commands:    []string{fix.Command(ctx.sudoFor(n.Info.UID), "sed", "-i", `s/\r$//`, n.Path)},
					Risk:        core.RiskLow,
					Note:        "or: dos2unix " + fix.Quote(n.Path),
				},
			}
		case sb.Interpreter == "":
			f.Severity = core.Blocker
			f.Summary = "empty #! line"
			f.Detail = fmt.Sprintf("%s starts with #! but names no interpreter, so execve fails with \"Exec format error\".", n.Path)
		case !path.IsAbs(sb.Interpreter):
			f.Severity = core.Warn
			f.Summary = "relative interpreter path"
			f.Detail = fmt.Sprintf("The #! line of %s names %s, a relative path: it is looked up from whatever\ndirectory the program is started in, so it may work in one place and not another.", n.Path, sb.Interpreter)
		default:
			return nil
		}

	case core.ExecELF:
		return elfFindings(ctx, n, f)

	case core.ExecUnknownFormat:
		f.Severity = core.Blocker
		f.Confidence = core.Likely
		f.Summary = "not a recognized executable format"
		f.Detail = fmt.Sprintf("%s neither starts with #! nor is an ELF binary, so execve fails with\n\"Exec format error\". Shells fall back to running such files as sh scripts, so it\nmay still work when started from a shell.", n.Path)
		f.Fixes = []core.Fix{{Description: "Add a #! line naming its interpreter, e.g. #!/bin/sh", Risk: core.RiskLow}}
	}
	return []core.Finding{f}
}

func elfFindings(ctx *Context, n *core.Node, f core.Finding) []core.Finding {
	e := n.Exec.ELF
	if e == nil {
		f.Severity = core.Blocker
		f.Confidence = core.Likely
		f.Summary = "malformed ELF header"
		f.Detail = fmt.Sprintf("%s looks like an ELF binary but its header is damaged (%v), so it will\nprobably fail with \"Exec format error\".", n.Path, n.Exec.Err)
		return []core.Finding{f}
	}
	native, compat := binfmt.HostMachine(ctx.HostArch)
	if native == 0 || e.Machine == native {
		return nil
	}
	theirs := binfmt.MachineName(e.Machine, e.Class)
	ours := binfmt.MachineName(native, 64)
	if q := binfmt.QemuName(e.Machine, e.Class); q != "" && ctx.Sys != nil {
		if names, err := ctx.Sys.ReadDirNames("/proc/sys/fs/binfmt_misc"); err == nil {
			for _, name := range names {
				if name == q {
					f.Severity = core.Info
					f.Summary = "runs through " + q + " emulation"
					f.Detail = fmt.Sprintf("%s is %s %s binary on %s %s machine; binfmt_misc hands it to %s.", n.Path, article(theirs), theirs, article(ours), ours, q)
					return []core.Finding{f}
				}
			}
		}
	}
	if e.Machine == compat {
		f.Severity = core.Warn
		f.Confidence = core.Possible
		f.Summary = "32-bit " + theirs + " binary"
		f.Detail = fmt.Sprintf("%s is a 32-bit %s binary. It runs on this %s machine only if the kernel\nhas 32-bit support and the 32-bit libraries are installed.", n.Path, theirs, ours)
		return []core.Finding{f}
	}
	f.Severity = core.Blocker
	f.Summary = fmt.Sprintf("built for %s, but this machine is %s", theirs, ours)
	f.Detail = fmt.Sprintf("%s is %s %s binary and this machine is %s, so execve fails with\n\"Exec format error\".", n.Path, article(theirs), theirs, ours)
	f.Fixes = []core.Fix{{Description: fmt.Sprintf("Install the %s build of this program", ours), Risk: core.RiskLow}}
	return []core.Finding{f}
}

// lookupMissing explains a missing interpreter or loader component.
func lookupMissing(n *core.Node, f core.Finding) core.Finding {
	l := n.Lookup
	switch l.Role {
	case core.RoleInterpreter:
		f.Summary = "interpreter does not exist"
		f.Detail = fmt.Sprintf("The #! line of %s names %s, which does not exist, so running it fails\nwith \"bad interpreter: No such file or directory\".", l.For.Path, l.Path)
		f.Fixes = []core.Fix{{Description: "Install " + path.Base(l.Path) + ", or fix the #! line to point at an installed interpreter", Risk: core.RiskLow}}
	case core.RoleLoader:
		f.Summary = "dynamic loader does not exist"
		f.Detail = fmt.Sprintf("%s needs the dynamic loader %s, which does not exist. That is why running\nit fails with \"No such file or directory\" even though the file is there. It was\nprobably built for another system, such as a glibc program on musl-based Alpine\nor the reverse.", l.For.Path, l.Path)
		f.Fixes = []core.Fix{{Description: "Install the C library it was built against, or use a statically linked build", Risk: core.RiskLow}}
	}
	return f
}

// article picks "a" or "an" for an architecture name.
func article(name string) string {
	if name != "" && strings.ContainsRune("aeiouAEIOUx", rune(name[0])) {
		return "an" // "an x86_64" is read "an ex-86"
	}
	return "a"
}
