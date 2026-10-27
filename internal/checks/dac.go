package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/muneeb-devp/whycant/internal/acl"
	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/fix"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// DAC evaluates discretionary access control: the owner/group/other mode
// bits, or the POSIX ACL when one is present, with root's capability
// overrides. Class selection follows the kernel exactly.
type DAC struct{}

// Name implements Check.
func (DAC) Name() string { return "dac" }

// Applies implements Check.
func (DAC) Applies(ctx *Context, n *core.Node) bool { return inspectable(ctx, n) && n.Need != 0 }

// Kinds of decisions, i.e. which entry of the mode or ACL the kernel used.
const (
	kindOwner     = "owner"
	kindNamedUser = "named user"
	kindGroup     = "group"
	kindOther     = "other"
)

// decision is the single mode class or ACL entry the kernel consults.
type decision struct {
	kind string
	raw  core.Perm // permission of the entry
	bits core.Perm // after the ACL mask
	// mask is the ACL mask, when an ACL with a mask decided.
	mask    core.Perm
	hasMask bool
	// entry names the ACL entry, e.g. "user:www-data"; empty without an ACL.
	entry string
	// groupEntries describes every matching ACL group entry, for denials.
	groupEntries []string
}

// masked reports whether the entry grants need but the mask takes it away.
func (d decision) masked(need core.Perm) bool {
	return d.hasMask && d.raw&need == need && d.bits&need != need
}

// decide picks the kernel's permission source for s on n.
func decide(ctx *Context, n *core.Node) decision {
	s, fi := ctx.Subject, n.Info
	// acl_permission_check() only consults the ACL when the group bits
	// (which hold the mask) are not empty; otherwise the mode decides.
	if n.ACL == nil || fi.Mode&0o070 == 0 {
		switch {
		case s.UID == fi.UID:
			p := permOf(fi, 0)
			return decision{kind: kindOwner, raw: p, bits: p}
		case s.InGroup(fi.GID):
			p := permOf(fi, 1)
			return decision{kind: kindGroup, raw: p, bits: p}
		}
		p := permOf(fi, 2)
		return decision{kind: kindOther, raw: p, bits: p}
	}

	// ACL order: owner, named users, owning group and named groups, other.
	// Named entries and the owning group are limited by the mask.
	a := n.ACL
	m, hasMask := a.Mask()
	mask := aclPerm(m)
	if s.UID == fi.UID {
		e, _ := a.Find(acl.TagUserObj, 0)
		return decision{kind: kindOwner, raw: aclPerm(e.Perm), bits: aclPerm(e.Perm)}
	}
	if e, ok := a.Find(acl.TagUser, s.UID); ok {
		return decision{
			kind: kindNamedUser, raw: aclPerm(e.Perm), bits: aclPerm(e.Perm) & mask,
			mask: mask, hasMask: hasMask, entry: "user:" + ctx.userName(s.UID),
		}
	}
	// The kernel uses the first matching group entry that grants the
	// request, then applies the mask; if none grants it, access is denied.
	var first *decision
	var matched []string
	for _, e := range a.Entries {
		var name string
		switch {
		case e.Tag == acl.TagGroupObj && s.InGroup(fi.GID):
			name = "group::" // the owning group
		case e.Tag == acl.TagGroup && s.InGroup(e.ID):
			name = "group:" + ctx.groupName(e.ID)
		default:
			continue
		}
		d := decision{
			kind: kindGroup, raw: aclPerm(e.Perm), bits: aclPerm(e.Perm) & mask,
			mask: mask, hasMask: hasMask, entry: name,
		}
		matched = append(matched, fmt.Sprintf("%s %s", name, d.raw))
		if d.raw&n.Need == n.Need {
			d.groupEntries = matched
			return d
		}
		if first == nil {
			first = &d
		}
	}
	if first != nil {
		first.groupEntries = matched
		first.bits = 0 // no matching entry grants the request
		return *first
	}
	e, _ := a.Find(acl.TagOther, 0)
	return decision{kind: kindOther, raw: aclPerm(e.Perm), bits: aclPerm(e.Perm)}
}

// capAllows mirrors the capability overrides in generic_permission(). They
// apply to a whole request, not bit by bit:
//   - directories: CAP_DAC_READ_SEARCH for requests without w, else
//     CAP_DAC_OVERRIDE;
//   - files: CAP_DAC_READ_SEARCH only for a read-only request;
//     CAP_DAC_OVERRIDE unless x is requested and no x bit is set at all.
func capAllows(s *core.Subject, fi sys.FileInfo, req core.Perm) bool {
	if fi.IsDir() {
		if req&core.PermW == 0 && s.Caps.Has(core.CapDACReadSearch) {
			return true
		}
		return s.Caps.Has(core.CapDACOverride)
	}
	if req == core.PermR && s.Caps.Has(core.CapDACReadSearch) {
		return true
	}
	return (req&core.PermX == 0 || fi.Perm()&0o111 != 0) && s.Caps.Has(core.CapDACOverride)
}

// aclPerm converts an ACL entry's rwx bits.
func aclPerm(p uint16) core.Perm { return core.Perm(p & 7) }

// permOf returns the owner (0), group (1) or other (2) bits of the mode.
func permOf(fi sys.FileInfo, class uint) core.Perm {
	return core.Perm(fi.Mode >> (3 * (2 - class)) & 7)
}

// Evaluate implements Check.
func (DAC) Evaluate(ctx *Context, n *core.Node) []core.Finding {
	s, fi := ctx.Subject, n.Info
	d := decide(ctx, n)

	// The kernel checks each permission request as a whole. A script's x
	// (execve) and r (the interpreter reopening it) are separate requests.
	requests := []core.Perm{n.Need}
	if n.Exec != nil && n.Exec.Kind == core.ExecScript && n.Need == core.PermR|core.PermX {
		requests = []core.Perm{core.PermX, core.PermR}
	}
	var missing core.Perm
	override := false
	for _, req := range requests {
		switch {
		case d.bits&req == req:
		case capAllows(s, fi, req):
			override = true
		default:
			missing |= req &^ d.bits
		}
	}

	f := core.Finding{Check: "dac", NodePath: n.Path, Confidence: networkConfidence(n)}
	if missing == 0 {
		f.Severity = core.Pass
		switch {
		case override:
			f.Summary = s.Who() + " bypasses the permission bits"
		case d.entry != "":
			f.Summary = fmt.Sprintf("ACL entry %s gives %s, which includes %s", d.entry, d.bits, n.Need.Short())
		default:
			f.Summary = fmt.Sprintf("%s permissions %s include %s", d.kind, d.bits, n.Need.Short())
		}
		out := []core.Finding{f}
		canSearch := d.bits&core.PermX != 0 || capAllows(s, fi, core.PermX)
		if w, ok := listWithoutX(ctx, n, canSearch); ok {
			out = append(out, w)
		}
		return out
	}

	f.Severity = core.Blocker
	if s.Caps.Has(core.CapDACOverride) && !fi.IsDir() {
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

	if d.masked(n.Need) {
		f.Summary = "the ACL mask removes " + permWords(missing) + " permission"
	} else {
		f.Summary = fmt.Sprintf("%s class has no %s permission", d.kind, permWords(missing))
	}
	f.Detail = explain(ctx, n, d)
	f.Fixes = dacFixes(ctx, n, d, missing)
	if gid, ok := staleGrant(ctx, n); ok {
		staleExplain(ctx, gid, &f)
	}
	return []core.Finding{f}
}

// staleGrant finds a group the subject was configured into but whose
// membership is not active yet, and that would grant the access.
func staleGrant(ctx *Context, n *core.Node) (uint32, bool) {
	s := ctx.Subject
	for _, gid := range s.StaleGroups {
		with := *s
		with.Groups = append(append([]uint32{}, s.Groups...), gid)
		c := *ctx
		c.Subject = &with
		if decide(&c, n).bits&n.Need == n.Need {
			return gid, true
		}
	}
	return 0, false
}

// staleExplain turns a DAC finding into the stale-group explanation, which
// is the real cause: the fix is a new session, not a permission change.
func staleExplain(ctx *Context, gid uint32, f *core.Finding) {
	name := ctx.groupName(gid)
	s := ctx.Subject
	who, when := "this login session", "log out and back in"
	if !s.Current {
		who, when = "the process", "restart it"
	}
	f.Summary = fmt.Sprintf("group %q is configured but not active yet", name)
	f.Detail = fmt.Sprintf("%s was added to group %q, which would allow this, but %s started\nbefore that and does not have the group yet. Group changes only apply to new\nsessions and restarted services; %s.",
		s.Who(), name, who, when)
	// Joining the group again would not help; keep only fixes that do.
	var kept []core.Fix
	for _, fx := range f.Fixes {
		if !strings.Contains(strings.Join(fx.Commands, " "), "usermod") {
			kept = append(kept, fx)
		}
	}
	f.Fixes = kept
	fx := core.Fix{
		Description: "Start a session with the new group",
		Risk:        core.RiskLow,
		Note:        "or simply log out and back in",
	}
	if s.Current {
		fx.Commands = []string{fix.Command(false, "newgrp", name)}
	} else {
		fx = core.Fix{Description: "Restart the process so it picks up its new groups", Risk: core.RiskLow}
	}
	f.Fixes = append([]core.Fix{fx}, f.Fixes...)
}

// networkConfidence lowers confidence where the server, not the local
// kernel, has the final say.
func networkConfidence(n *core.Node) core.Confidence {
	if n.Mount != nil && isNetworkFS(n.Mount.FSType) {
		return core.Likely
	}
	return core.Certain
}

func explain(ctx *Context, n *core.Node, d decision) string {
	s, fi := ctx.Subject, n.Info
	need := needSentence(ctx, n)
	group, other := permOf(fi, 1), permOf(fi, 2)

	if d.masked(n.Need) {
		return fmt.Sprintf("The ACL entry %s grants %s, but the ACL mask is %s,\nso the effective permission is %s. %s\n(On a file with an ACL, chmod g=... changes the mask.)",
			d.entry, d.raw, d.mask, d.bits, need)
	}

	switch d.kind {
	case kindOwner:
		text := fmt.Sprintf("%s owns %s, so only the owner permissions apply: %s.\n%s", s.Who(), n.Path, d.bits, need)
		if n.ACL == nil && (group|other)&n.Need == n.Need {
			text += fmt.Sprintf("\nThe group (%s) and other (%s) permissions would allow it, but they never\napply to the owner: owner bits are used on their own.", group, other)
		}
		return text
	case kindNamedUser:
		return fmt.Sprintf("The ACL entry %s gives %s only %s on %s. %s", d.entry, s.Who(), d.bits, n.Path, need)
	case kindGroup:
		if n.ACL != nil {
			return fmt.Sprintf("%s is not the owner (%s). The ACL group entries that match it\n(%s) do not grant %s. %s",
				s.Who(), n.OwnerName, strings.Join(d.groupEntries, ", "), n.Need.Short(), need)
		}
		text := fmt.Sprintf("%s is not the owner (%s) but is in group %q,\nso the group permissions apply: %s. %s", s.Who(), n.OwnerName, n.GroupName, d.bits, need)
		if other&n.Need == n.Need {
			text += fmt.Sprintf("\nThe other permissions (%s) would allow it, but they never apply to members\nof the file's group.", other)
		}
		return text
	}
	text := fmt.Sprintf("%s is not the owner (%s) and is not in group %q,\nso the \"other\" permissions apply: %s. %s", s.Who(), n.OwnerName, n.GroupName, d.bits, need)
	if n.ACL != nil {
		text += fmt.Sprintf("\nThe ACL on %s has no entry for %s or its groups.", n.Path, s.Who())
	}
	return text
}

func dacFixes(ctx *Context, n *core.Node, d decision, missing core.Perm) []core.Fix {
	s, fi := ctx.Subject, n.Info
	sudo := ctx.sudoFor(fi.UID)

	if d.masked(n.Need) {
		return []core.Fix{{
			Description: "Widen the ACL mask to " + (d.mask | n.Need).String(),
			Commands:    []string{fix.Command(sudo, "setfacl", "-m", "m::"+(d.mask|n.Need).Short(), n.Path)},
			Risk:        core.RiskLow,
			Note:        "the mask also limits the owning group and every other named entry",
		}}
	}
	if d.kind == kindOwner {
		return []core.Fix{{
			Description: fmt.Sprintf("Give the owner (%s) the missing %s permission", s.Who(), missing.Short()),
			Commands:    []string{fix.Command(sudo, "chmod", "u+"+missing.Short(), n.Path)},
			Risk:        core.RiskLow,
		}}
	}

	aclUser := s.Name
	if aclUser == "" {
		aclUser = strconv.FormatUint(uint64(s.UID), 10)
	}
	fixes := []core.Fix{{
		Description: fmt.Sprintf("Grant %s only to %s via ACL", accessWord(ctx, n), s.Who()),
		Commands:    []string{fix.Command(sudo, "setfacl", "-m", "u:"+aclUser+":"+(d.raw|n.Need).Short(), n.Path)},
		Risk:        core.RiskLow,
	}}
	if d.kind == kindNamedUser {
		fixes[0].Description = fmt.Sprintf("Extend the ACL entry for %s", s.Who())
		return fixes
	}

	ownerGroup := permOf(fi, 1)
	if n.ACL != nil {
		if e, ok := n.ACL.Find(acl.TagGroupObj, 0); ok {
			m, _ := n.ACL.Mask()
			ownerGroup = aclPerm(e.Perm & m)
		}
	}
	switch {
	case d.kind == kindGroup && n.ACL == nil:
		fixes = append(fixes, core.Fix{
			Description: fmt.Sprintf("Give group %q the missing %s permission", n.GroupName, missing.Short()),
			Commands:    []string{fix.Command(sudo, "chmod", "g+"+missing.Short(), n.Path)},
			Risk:        core.RiskMedium,
			Note:        fmt.Sprintf("this affects every member of %s", n.GroupName),
		})
	case d.kind == kindOther && ownerGroup&n.Need == n.Need && s.Name != "" && !privilegedGroup(fi.GID, n.GroupName):
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
func listWithoutX(ctx *Context, n *core.Node, canSearch bool) (core.Finding, bool) {
	if ctx.Action != core.List || n.Role != core.RoleTarget || canSearch {
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
	switch {
	case n.Role == core.RoleParent:
		if ctx.Action == core.Create {
			return "Creating an entry in a directory needs w and x."
		}
		return "Deleting or renaming an entry in a directory needs w and x."
	case n.Role == core.RoleAncestor || ctx.Action == core.Traverse:
		return "Entering a directory needs x."
	case n.Role == core.RoleInterpreter:
		return "Running a script needs x on its interpreter."
	case n.Role == core.RoleLoader:
		return "Running a dynamically linked program needs x on its loader."
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
		if n.Need&core.PermR != 0 {
			return "Running a script needs r and x, because the interpreter has to read it."
		}
		return "Running a file needs x."
	case core.List:
		return "Listing a directory needs r."
	}
	return ""
}

func accessWord(ctx *Context, n *core.Node) string {
	switch {
	case n.Role == core.RoleParent:
		return "write access to the directory"
	case n.Role == core.RoleAncestor || ctx.Action == core.Traverse:
		return "traverse"
	case n.Role == core.RoleInterpreter || n.Role == core.RoleLoader:
		return "execute access"
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

// privilegedGroup reports groups whose membership grants far more than one
// file (root equivalence, raw disks, the shadow file...). whycant never
// suggests joining them.
func privilegedGroup(gid uint32, name string) bool {
	if gid == 0 {
		return true
	}
	switch name {
	case "root", "wheel", "sudo", "admin", "adm", "shadow", "docker", "disk", "kmem", "lxd", "libvirt", "systemd-journal":
		return true
	}
	return false
}
