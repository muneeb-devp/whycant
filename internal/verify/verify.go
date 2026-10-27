// Package verify cross-checks an analysis against the kernel: it re-runs
// whycant as the subject (the hidden __probe subcommand) and asks
// access(2). It never modifies anything.
package verify

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"syscall"

	"github.com/muneeb-devp/whycant/internal/checks"
	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/engine"
	"github.com/muneeb-devp/whycant/internal/sys"
	"github.com/muneeb-devp/whycant/internal/walk"
)

// Subcommand is the hidden command the probe runs as.
const Subcommand = "__probe"

// Probe exit codes.
const (
	probeAllowed = 0
	probeDenied  = 1
	probeError   = 2
)

// AccessFor maps an action on absPath to what access(2) can check: the
// path itself, or for create and delete the directory that holds it.
func AccessFor(action core.Action, absPath string) (string, uint32) {
	switch action {
	case core.Read, core.List:
		return absPath, sys.AccessR
	case core.Write, core.Append:
		return absPath, sys.AccessW
	case core.Exec, core.Traverse:
		return absPath, sys.AccessX
	}
	return parentDir(absPath), sys.AccessW | sys.AccessX
}

// parentDir drops the last component without cleaning the rest: ".." must
// stay for the kernel to resolve after symlinks.
func parentDir(p string) string {
	p = strings.TrimRight(p, "/")
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

// RunProbe implements "whycant __probe <action> <path>". It must already be
// running with the subject's credentials.
func RunProbe(s sys.System, args []string, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: whycant __probe <action> <path>")
		return probeError
	}
	action, err := core.ParseAction(args[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return probeError
	}
	p, mode := AccessFor(action, args[1])
	err = s.Access(p, mode)
	switch {
	case err == nil:
		return probeAllowed
	case errors.Is(err, fs.ErrPermission), errors.Is(err, fs.ErrNotExist),
		errors.Is(err, syscall.EROFS), errors.Is(err, syscall.ENOTDIR),
		errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ETXTBSY):
		fmt.Fprintln(stderr, err)
		return probeDenied
	}
	fmt.Fprintln(stderr, err)
	return probeError
}

// AccessChecks are the checks whose rules access(2) also applies. Sticky
// directories, append-only files, script readability, interpreters and
// LSM decisions for another program are not visible to access(2).
func AccessChecks() []checks.Check {
	return []checks.Check{checks.Path{}, checks.Mount{}, checks.Attrs{}, checks.Protected{}, checks.DAC{}}
}

// Expected re-runs the analysis restricted to what access(2) checks, so it
// can be compared with the probe fairly.
func Expected(ctx *checks.Context, absPath string) (core.Verdict, error) {
	p, _ := AccessFor(ctx.Action, absPath)
	walkAction := ctx.Action
	if ctx.Action == core.Create || ctx.Action == core.Delete {
		walkAction = core.Traverse
	}
	nodes, err := walk.Walk(ctx.Sys, walkAction, p)
	if err != nil {
		return 0, err
	}
	final := nodes[len(nodes)-1]
	switch ctx.Action {
	case core.Create, core.Delete:
		final.Role = core.RoleParent
		final.Need = core.PermW | core.PermX
	case core.Exec:
		final.Need, final.Exec = core.PermX, nil
	}
	c := *ctx
	c.AccessOnly = true
	return engine.Run(&c, nodes, AccessChecks(), false).Verdict, nil
}

// Run probes the kernel as the subject and compares the answer with the
// analysis. It returns nil when verification is not possible at all.
func Run(ctx *checks.Context, absPath string) *core.VerifyResult {
	s := ctx.Subject
	if ctx.Sys.Getuid() != 0 {
		return &core.VerifyResult{Error: "--verify needs root, to run the probe as " + s.Who()}
	}
	if s.UID != 0 && s.Caps != 0 {
		return &core.VerifyResult{Error: "the process has capabilities that a probe cannot reproduce"}
	}
	if s.UID == 0 && (!s.Caps.Has(core.CapDACOverride) || !s.Caps.Has(core.CapDACReadSearch)) {
		return &core.VerifyResult{Error: "the process runs as root without full capabilities, which a probe cannot reproduce"}
	}
	expected, err := Expected(ctx, absPath)
	if err != nil {
		return &core.VerifyResult{Error: err.Error()}
	}
	if expected == core.Indeterminate {
		return &core.VerifyResult{Error: "the analysis was inconclusive, so there is nothing to compare"}
	}

	cred := sys.Credential{UID: s.UID, GID: s.GID, Groups: s.Groups}
	code, stderr, err := ctx.Sys.Probe(cred, Subcommand, ctx.Action.String(), absPath)
	if err != nil {
		return &core.VerifyResult{Error: fmt.Sprintf("the probe could not start as %s (%v); whycant's own binary must be executable by that user", s.Who(), err)}
	}
	var probe core.Verdict
	switch code {
	case probeAllowed:
		probe = core.Allowed
	case probeDenied:
		probe = core.Denied
	default:
		msg := stderr
		if msg == "" {
			msg = fmt.Sprintf("exit status %d", code)
		}
		return &core.VerifyResult{Error: "the probe failed: " + msg}
	}
	return &core.VerifyResult{Probe: probe, Match: probe == expected}
}
