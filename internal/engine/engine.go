// Package engine runs the checks over the chain and decides the verdict.
package engine

import (
	"github.com/muneeb-devp/whycant/internal/checks"
	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
)

// Run evaluates nodes in order with each applicable check. It stops after the
// first node with a blocker unless all is set, and always stops at a node
// whycant could not inspect, since nothing beyond it is known.
func Run(ctx *checks.Context, nodes []*core.Node, list []checks.Check, all bool) *core.Result {
	r := &core.Result{
		Action:  ctx.Action,
		Path:    nodes[len(nodes)-1].Path,
		Subject: ctx.Subject,
		Chain:   nodes,
	}

	for _, n := range nodes {
		if !n.Exists && n.Err == nil {
			break // the walk never reached this node
		}
		n.Evaluated = true
		n.Result = core.Pass
		for _, c := range list {
			if !c.Applies(ctx, n) {
				continue
			}
			for _, f := range c.Evaluate(ctx, n) {
				fix.Rank(f.Fixes)
				n.Result = max(n.Result, f.Severity)
				r.Findings = append(r.Findings, f)
			}
		}
		if n.Result == core.Unknown || (n.Result == core.Blocker && !all) {
			break
		}
	}

	r.Verdict, r.Confidence = verdict(r.Findings)
	return r
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
