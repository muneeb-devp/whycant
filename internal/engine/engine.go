// Package engine runs the checks over the chain and decides the verdict.
package engine

import (
	"path"
	"strings"

	"github.com/muneeb-devp/whycant/internal/checks"
	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
	"github.com/muneeb-devp/whycant/internal/walk"
)

// MaxInterpreterDepth bounds #! chains (a script whose interpreter is a
// script...), like the kernel's own limit of a few levels.
const MaxInterpreterDepth = 4

// DefaultPATH is used to resolve "#!/usr/bin/env prog". Services may run
// with a different PATH, so findings that depend on it are "likely".
var DefaultPATH = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

type runner struct {
	ctx     *checks.Context
	list    []checks.Check
	all     bool
	result  *core.Result
	stopped bool
	seen    map[string]bool
}

// Run evaluates nodes in order with each applicable check. It stops after the
// first node with a blocker unless all is set, and always stops at a node
// whycant could not inspect, since nothing beyond it is known. For exec, the
// script interpreter or dynamic loader is then walked and checked too.
func Run(ctx *checks.Context, nodes []*core.Node, list []checks.Check, all bool) *core.Result {
	r := &runner{
		ctx: ctx, list: list, all: all, seen: map[string]bool{},
		result: &core.Result{
			Action:  ctx.Action,
			Path:    nodes[len(nodes)-1].Path,
			Subject: ctx.Subject,
		},
	}
	r.add(nodes)
	if ctx.Action == core.Exec {
		r.followExec(nodes[len(nodes)-1])
	}
	r.result.Verdict, r.result.Confidence = verdict(r.result.Findings)
	return r.result
}

// add appends nodes to the chain (skipping ones already there) and
// evaluates them unless the run has stopped.
func (r *runner) add(nodes []*core.Node) {
	for _, n := range nodes {
		if r.seen[n.Path] && n.Role != core.RoleInterpreter && n.Role != core.RoleLoader {
			continue
		}
		r.seen[n.Path] = true
		r.result.Chain = append(r.result.Chain, n)
		if r.stopped || (!n.Exists && n.Err == nil) {
			r.stopped = true // the walk never reached this node
			continue
		}
		r.evaluate(n)
	}
}

func (r *runner) evaluate(n *core.Node) {
	if n.Exists && r.ctx.Names != nil && n.OwnerName == "" {
		n.OwnerName = r.ctx.Names.UserName(n.Info.UID)
		n.GroupName = r.ctx.Names.GroupName(n.Info.GID)
	}
	n.Evaluated = true
	n.Result = core.Pass
	for _, c := range r.list {
		if !c.Applies(r.ctx, n) {
			continue
		}
		for _, f := range c.Evaluate(r.ctx, n) {
			r.addFinding(n, f)
		}
	}
	if n.Result == core.Unknown || (n.Result == core.Blocker && !r.all) {
		r.stopped = true
	}
}

func (r *runner) addFinding(n *core.Node, f core.Finding) {
	fix.Rank(f.Fixes)
	n.Result = max(n.Result, f.Severity)
	r.result.Findings = append(r.result.Findings, f)
}

// followExec walks what execve loads after the file itself: the #!
// interpreter of a script (through env if needed), or an ELF binary's
// dynamic loader, recursively.
func (r *runner) followExec(target *core.Node) {
	for depth := 0; depth < MaxInterpreterDepth && !r.stopped; depth++ {
		x := target.Exec
		if x == nil || target.Result == core.Blocker {
			return
		}
		var next string
		role := core.RoleInterpreter
		switch x.Kind {
		case core.ExecScript:
			if x.Shebang.CRLF || x.Shebang.Interpreter == "" {
				return
			}
			next = x.Shebang.Interpreter
		case core.ExecELF:
			if x.ELF == nil || x.ELF.Interp == "" {
				return
			}
			next, role = x.ELF.Interp, core.RoleLoader
		default:
			return
		}

		last := r.lookup(next, role, target)
		if last == nil {
			return
		}
		if x.Kind == core.ExecScript && path.Base(next) == "env" && last.Result != core.Blocker {
			if prog := envProgram(x.Shebang.Arg); prog != "" {
				if last = r.resolveEnv(prog, last, target); last == nil {
					return
				}
			}
		}
		target = last
	}
}

// lookup walks an interpreter or loader path and adds it to the chain.
func (r *runner) lookup(p string, role core.Role, forNode *core.Node) *core.Node {
	nodes, err := walk.Walk(r.ctx.Sys, core.Exec, p)
	if err != nil || len(nodes) == 0 {
		return nil
	}
	l := &core.Lookup{Role: role, Path: p, For: forNode}
	for _, n := range nodes {
		n.Lookup = l
	}
	last := nodes[len(nodes)-1]
	last.Role = role
	r.add(nodes)
	return last
}

// resolveEnv finds prog on the default PATH, as env would, and adds it.
func (r *runner) resolveEnv(prog string, env, script *core.Node) *core.Node {
	if strings.Contains(prog, "/") {
		return r.lookup(prog, core.RoleInterpreter, script)
	}
	for _, dir := range DefaultPATH {
		candidate := path.Join(dir, prog)
		if _, err := r.ctx.Sys.Lstat(candidate); err == nil {
			return r.lookup(candidate, core.RoleInterpreter, script)
		}
	}
	f := core.Finding{
		Check: "exec", NodePath: env.Path, Severity: core.Blocker, Confidence: core.Likely,
		Summary: prog + " is not on PATH",
		Detail: "The #! line of " + script.Path + " runs " + prog + " through env, but " + prog + " is not in\n" +
			strings.Join(DefaultPATH, ":") + ", so env fails with \"No such file or directory\".\n" +
			"(A service may run with a different PATH.)",
		Fixes: []core.Fix{{Description: "Install " + prog + ", or put its full path in the #! line", Risk: core.RiskLow}},
	}
	r.addFinding(env, f)
	if !r.all {
		r.stopped = true
	}
	return nil
}

// envProgram returns the program env would run from a #! argument such as
// "python3", "-S python3 -u" or "-i bash".
func envProgram(arg string) string {
	fields := strings.Fields(arg)
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "-S" || f == "--split-string":
			continue
		case f == "-u" || f == "--unset" || f == "-C" || f == "--chdir":
			i++ // takes a value
		case strings.HasPrefix(f, "-"), strings.Contains(f, "="):
			continue
		default:
			return f
		}
	}
	return ""
}

// verdict is denied if anything blocks, unknown if something could not be
// determined, and allowed otherwise. Confidence is the weakest confidence
// among the deciding findings.
func verdict(findings []core.Finding) (core.Verdict, core.Confidence) {
	conf := core.Certain
	blocked, unknown := false, false
	for _, f := range findings {
		switch f.Severity {
		case core.Blocker:
			blocked = true
			conf = max(conf, f.Confidence)
		case core.Unknown:
			unknown = true
		}
	}
	switch {
	case blocked:
		return core.Denied, conf
	case unknown:
		return core.Indeterminate, core.Certain
	}
	return core.Allowed, core.Certain
}
