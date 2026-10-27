package core

import (
	"fmt"
	"strconv"

	"github.com/muneeb-devp/whycant/internal/acl"
	"github.com/muneeb-devp/whycant/internal/binfmt"
	"github.com/muneeb-devp/whycant/internal/mount"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// Capability numbers from linux/capability.h that affect file access.
const (
	CapDACOverride   = 1
	CapDACReadSearch = 2
	CapFowner        = 3
)

// CapSet is a bitmask of effective capabilities.
type CapSet uint64

// AllCaps is the full capability set root has by default.
const AllCaps = ^CapSet(0)

// Has reports whether capability c is in the set.
func (c CapSet) Has(capability int) bool { return c&(1<<capability) != 0 }

// Subject is the identity whose access is being checked.
type Subject struct {
	Name        string // empty when the uid has no passwd entry
	UID         uint32
	GID         uint32
	Groups      []uint32 // every group in effect, including GID
	Caps        CapSet
	Label       string   // SELinux context / AppArmor profile, when known
	Source      string   // "nss", "files", "session", "pid:1234"
	StaleGroups []uint32 // configured but not active in the session
	// Current is true when the subject is the user running whycant, so the
	// session's real groups were used.
	Current bool
	// PID and Process are set for --pid subjects.
	PID     int
	Process string
}

// InGroup reports whether gid is the subject's primary or a supplementary group.
func (s *Subject) InGroup(gid uint32) bool {
	if s.GID == gid {
		return true
	}
	for _, g := range s.Groups {
		if g == gid {
			return true
		}
	}
	return false
}

// Who names the subject in prose: "www-data", or "uid 1234" without a name.
func (s *Subject) Who() string {
	if s.Name != "" {
		return s.Name
	}
	return "uid " + strconv.FormatUint(uint64(s.UID), 10)
}

// Display names the subject with its uid: "www-data (uid 33)", or for a
// process "nginx (pid 812, www-data, uid 33)".
func (s *Subject) Display() string {
	who := s.Who()
	if s.Name != "" {
		who = fmt.Sprintf("%s, uid %d", s.Name, s.UID)
	}
	if s.PID != 0 {
		return fmt.Sprintf("%s (pid %d, %s)", s.Process, s.PID, who)
	}
	if s.Name != "" {
		return fmt.Sprintf("%s (uid %d)", s.Name, s.UID)
	}
	return who
}

// Role is why a node is part of the chain.
type Role int

// Roles.
const (
	RoleAncestor Role = iota + 1
	RoleTarget
	RoleParent
	RoleSymlink
	RoleInterpreter
	RoleLoader
)

func (r Role) String() string {
	switch r {
	case RoleAncestor:
		return "ancestor"
	case RoleTarget:
		return "target"
	case RoleParent:
		return "parent"
	case RoleSymlink:
		return "symlink"
	case RoleInterpreter:
		return "interpreter"
	case RoleLoader:
		return "loader"
	}
	return fmt.Sprintf("Role(%d)", int(r))
}

// Node is one path component in the access chain.
type Node struct {
	Path     string // as walked
	Resolved string // after symlinks
	Role     Role
	Need     Perm // what this node must grant
	Info     sys.FileInfo
	// Exists is true when Info was filled by a successful lstat.
	Exists bool
	// Err is the lstat error, if the walk got this far and lstat failed.
	Err error

	OwnerName string // resolved from Info.UID, or the number
	GroupName string // resolved from Info.GID, or the number

	// Dir is the directory node this node was looked up in; nil for "/".
	Dir *Node
	// ACL is the access ACL when it holds more than the mode bits express.
	ACL *acl.ACL
	// DefaultACL is the directory's default ACL, if any.
	DefaultACL *acl.ACL
	Mount      *mount.Mount
	// Flags are the inode attributes; FlagsKnown is false when they could
	// not be read (unsupported filesystem, or whycant cannot open the file).
	Flags      uint32
	FlagsKnown bool
	FlagsErr   error // why the flags could not be read

	// Exec describes the file's executable format, for exec targets,
	// interpreters and loaders.
	Exec *ExecInfo
	// Lookup is set on nodes walked to reach a script's interpreter or a
	// binary's dynamic loader.
	Lookup *Lookup

	Evaluated bool
	Result    Severity
}

// ExecKind is how execve would treat a file.
type ExecKind int

// Executable kinds.
const (
	ExecUnreadable ExecKind = iota // whycant could not read the file
	ExecScript                     // starts with #!
	ExecELF
	ExecUnknownFormat
)

// ExecInfo is what whycant learned from the start of an executable.
type ExecInfo struct {
	Kind    ExecKind
	Shebang binfmt.Shebang
	ELF     *binfmt.ELF // nil when Kind is ExecELF but the header was malformed
	Err     error
}

// Lookup ties a node to the interpreter or loader lookup it is part of.
type Lookup struct {
	Role Role   // RoleInterpreter or RoleLoader
	Path string // the interpreter or loader being looked up
	For  *Node  // the script or binary that needs it
}

// Severity of a finding, ordered so that larger values dominate a node's result.
type Severity int

// Severities.
const (
	Pass Severity = iota
	Info
	Warn
	Unknown
	Blocker
)

func (s Severity) String() string {
	switch s {
	case Pass:
		return "pass"
	case Info:
		return "info"
	case Warn:
		return "warn"
	case Unknown:
		return "unknown"
	case Blocker:
		return "blocker"
	}
	return fmt.Sprintf("Severity(%d)", int(s))
}

// Confidence in a finding, from most to least sure.
type Confidence int

// Confidences.
const (
	Certain Confidence = iota
	Likely
	Possible
)

func (c Confidence) String() string {
	switch c {
	case Certain:
		return "certain"
	case Likely:
		return "likely"
	case Possible:
		return "possible"
	}
	return fmt.Sprintf("Confidence(%d)", int(c))
}

// Risk of applying a fix; fixes are ranked lowest risk first.
type Risk int

// Risks.
const (
	RiskLow Risk = iota
	RiskMedium
	RiskHigh
)

func (r Risk) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	}
	return fmt.Sprintf("Risk(%d)", int(r))
}

// Finding is one conclusion a check reached about a node.
type Finding struct {
	Check      string
	NodePath   string
	Severity   Severity
	Confidence Confidence
	Summary    string // one line
	Detail     string // the "Why" paragraph; may contain line breaks
	Fixes      []Fix
}

// Fix is one suggested way to resolve a finding.
type Fix struct {
	Description string
	Commands    []string // shell-quoted, copy-paste ready
	Risk        Risk
	Note        string // e.g. "restart the service afterwards"
}

// Verdict is the overall answer.
type Verdict int

// Verdicts.
const (
	Allowed Verdict = iota
	Denied
	Indeterminate
)

func (v Verdict) String() string {
	switch v {
	case Allowed:
		return "allowed"
	case Denied:
		return "denied"
	case Indeterminate:
		return "unknown"
	}
	return fmt.Sprintf("Verdict(%d)", int(v))
}

// Result is the full outcome of an analysis.
type Result struct {
	Verdict    Verdict
	Confidence Confidence
	Action     Action
	Path       string
	Subject    *Subject
	Chain      []*Node
	Findings   []Finding
	Verify     *VerifyResult // set by --verify
}

// VerifyResult compares the analysis with the kernel's own access check.
type VerifyResult struct {
	Probe Verdict // what access(2) said, as the subject
	Match bool
	Error string // why the probe could not run, if it could not
}
