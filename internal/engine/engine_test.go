package engine

import (
	"testing"

	"github.com/muneeb-devp/whycant/internal/checks"
	"github.com/muneeb-devp/whycant/internal/core"
)

// stub is a check with canned severities per path.
type stub map[string]core.Severity

func (stub) Name() string                             { return "stub" }
func (stub) Applies(*checks.Context, *core.Node) bool { return true }
func (s stub) Evaluate(_ *checks.Context, n *core.Node) []core.Finding {
	sev, ok := s[n.Path]
	if !ok {
		return nil
	}
	return []core.Finding{{Check: "stub", NodePath: n.Path, Severity: sev, Fixes: []core.Fix{
		{Description: "risky", Risk: core.RiskHigh}, {Description: "safe", Risk: core.RiskLow},
	}}}
}

func chain(paths ...string) []*core.Node {
	nodes := make([]*core.Node, len(paths))
	for i, p := range paths {
		nodes[i] = &core.Node{Path: p, Exists: true}
	}
	return nodes
}

func evaluated(nodes []*core.Node) string {
	s := ""
	for _, n := range nodes {
		if n.Evaluated {
			s += "E"
		} else {
			s += "."
		}
	}
	return s
}

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		checks  stub
		all     bool
		verdict core.Verdict
		eval    string
		count   int
	}{
		{"allowed", stub{}, false, core.Allowed, "EEEE", 0},
		{"stops at first blocker", stub{"/b": core.Blocker, "/d": core.Blocker}, false, core.Denied, "EE..", 1},
		{"all continues", stub{"/b": core.Blocker, "/d": core.Blocker}, true, core.Denied, "EEEE", 2},
		{"unknown stops even with all", stub{"/b": core.Unknown, "/d": core.Blocker}, true, core.Indeterminate, "EE..", 1},
		{"blocker beats later unknown", stub{"/b": core.Blocker, "/c": core.Unknown}, true, core.Denied, "EEE.", 2},
		{"warnings do not deny", stub{"/c": core.Warn}, false, core.Allowed, "EEEE", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes := chain("/a", "/b", "/c", "/d")
			r := Run(&checks.Context{}, nodes, []checks.Check{tt.checks}, tt.all)
			if r.Verdict != tt.verdict || evaluated(nodes) != tt.eval || len(r.Findings) != tt.count {
				t.Errorf("verdict=%v eval=%s findings=%d; want %v %s %d",
					r.Verdict, evaluated(nodes), len(r.Findings), tt.verdict, tt.eval, tt.count)
			}
			for _, f := range r.Findings {
				if f.Fixes[0].Description != "safe" {
					t.Error("fixes not ranked")
				}
			}
		})
	}
}

func TestRunStopsAtUnwalkedNodes(t *testing.T) {
	nodes := chain("/a", "/b", "/c")
	nodes[2].Exists = false
	Run(&checks.Context{}, nodes, []checks.Check{stub{}}, true)
	if got := evaluated(nodes); got != "EE." {
		t.Errorf("evaluated = %s", got)
	}
}

func TestVerdictConfidence(t *testing.T) {
	v, c := verdict([]core.Finding{
		{Severity: core.Blocker, Confidence: core.Certain},
		{Severity: core.Blocker, Confidence: core.Likely},
	})
	if v != core.Denied || c != core.Likely {
		t.Errorf("verdict = %v %v", v, c)
	}
}
