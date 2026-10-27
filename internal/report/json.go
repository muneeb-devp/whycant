package report

import (
	"encoding/json"
	"io"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// SchemaVersion is bumped on any incompatible change to the JSON output.
const SchemaVersion = 1

// JSONResult is the --json document. Field names are part of the public
// interface; see the README.
type JSONResult struct {
	SchemaVersion int           `json:"schema_version"`
	Verdict       string        `json:"verdict"`
	Confidence    string        `json:"confidence"`
	Action        string        `json:"action"`
	Path          string        `json:"path"`
	Subject       JSONSubject   `json:"subject"`
	Chain         []JSONNode    `json:"chain"`
	Findings      []JSONFinding `json:"findings"`
	Warnings      []JSONFinding `json:"warnings"`
	Verify        *JSONVerify   `json:"verify"`
}

// JSONSubject describes who was checked.
type JSONSubject struct {
	Name        string   `json:"name"`
	UID         uint32   `json:"uid"`
	GID         uint32   `json:"gid"`
	Groups      []uint32 `json:"groups"`
	StaleGroups []uint32 `json:"stale_groups"`
	Source      string   `json:"source"`
	Label       string   `json:"label,omitempty"`
}

// JSONNode is one component of the chain.
type JSONNode struct {
	Path      string   `json:"path"`
	Resolved  string   `json:"resolved"`
	Role      string   `json:"role"`
	Need      string   `json:"need"`
	Exists    bool     `json:"exists"`
	Mode      string   `json:"mode,omitempty"`
	Owner     string   `json:"owner,omitempty"`
	Group     string   `json:"group,omitempty"`
	UID       *uint32  `json:"uid,omitempty"`
	GID       *uint32  `json:"gid,omitempty"`
	ACL       bool     `json:"acl"`
	Flags     []string `json:"flags"`
	Link      string   `json:"link,omitempty"`
	Mount     string   `json:"mount,omitempty"`
	FSType    string   `json:"fstype,omitempty"`
	Result    string   `json:"result"`
	Evaluated bool     `json:"evaluated"`
}

// JSONFinding is one finding with its fixes.
type JSONFinding struct {
	Check      string    `json:"check"`
	Path       string    `json:"path"`
	Severity   string    `json:"severity"`
	Confidence string    `json:"confidence"`
	Summary    string    `json:"summary"`
	Detail     string    `json:"detail"`
	Fixes      []JSONFix `json:"fixes"`
}

// JSONFix is one suggested fix.
type JSONFix struct {
	Description string   `json:"description"`
	Commands    []string `json:"commands"`
	Risk        string   `json:"risk"`
	Note        string   `json:"note"`
}

// JSONVerify is the --verify comparison.
type JSONVerify struct {
	Probe string `json:"probe"` // "allowed" or "denied"
	Match bool   `json:"match"`
	Error string `json:"error,omitempty"`
}

// ToJSON converts a result to the JSON document.
func ToJSON(r *core.Result) JSONResult {
	s := r.Subject
	out := JSONResult{
		SchemaVersion: SchemaVersion,
		Verdict:       r.Verdict.String(),
		Confidence:    r.Confidence.String(),
		Action:        r.Action.String(),
		Path:          r.Path,
		Subject: JSONSubject{
			Name: s.Name, UID: s.UID, GID: s.GID,
			Groups: nonNil(s.Groups), StaleGroups: nonNil(s.StaleGroups),
			Source: s.Source, Label: s.Label,
		},
		Chain:    []JSONNode{},
		Findings: []JSONFinding{},
		Warnings: []JSONFinding{},
	}
	for _, n := range r.Chain {
		out.Chain = append(out.Chain, jsonNode(n))
	}
	for _, f := range r.Findings {
		switch f.Severity {
		case core.Blocker, core.Unknown:
			out.Findings = append(out.Findings, jsonFinding(f))
		case core.Warn, core.Info:
			out.Warnings = append(out.Warnings, jsonFinding(f))
		}
	}
	if r.Verify != nil {
		out.Verify = &JSONVerify{Probe: r.Verify.Probe.String(), Match: r.Verify.Match, Error: r.Verify.Error}
	}
	return out
}

// JSON writes the result as indented JSON.
func JSON(w io.Writer, r *core.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(ToJSON(r))
}

func jsonNode(n *core.Node) JSONNode {
	j := JSONNode{
		Path: n.Path, Resolved: n.Resolved, Role: n.Role.String(), Need: n.Need.Short(),
		Exists: n.Exists, ACL: n.ACL != nil, Flags: []string{}, Evaluated: n.Evaluated,
		Result: "not_evaluated",
	}
	if n.Evaluated {
		j.Result = n.Result.String()
	}
	if n.Exists {
		uid, gid := n.Info.UID, n.Info.GID
		j.Mode, j.Owner, j.Group, j.UID, j.GID = n.Info.ModeString(), n.OwnerName, n.GroupName, &uid, &gid
		j.Link = n.Info.LinkTarget
	}
	if n.Flags&sys.FlagImmutable != 0 {
		j.Flags = append(j.Flags, "immutable")
	}
	if n.Flags&sys.FlagAppendOnly != 0 {
		j.Flags = append(j.Flags, "append_only")
	}
	if n.Mount != nil {
		j.Mount, j.FSType = n.Mount.MountPoint, n.Mount.FSType
	}
	return j
}

func jsonFinding(f core.Finding) JSONFinding {
	j := JSONFinding{
		Check: f.Check, Path: f.NodePath, Severity: f.Severity.String(), Confidence: f.Confidence.String(),
		Summary: f.Summary, Detail: f.Detail, Fixes: []JSONFix{},
	}
	for _, fx := range f.Fixes {
		j.Fixes = append(j.Fixes, JSONFix{
			Description: fx.Description, Commands: nonNilStrings(fx.Commands), Risk: fx.Risk.String(), Note: fx.Note,
		})
	}
	return j
}

func nonNil(ids []uint32) []uint32 {
	if ids == nil {
		return []uint32{}
	}
	return ids
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
