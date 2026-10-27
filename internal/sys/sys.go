// Package sys is the only place whycant touches the operating system.
//
// Everything else talks to the System interface, so checks can be tested
// against Fake without root, real users or a Linux kernel.
package sys

import "errors"

// System is every piece of OS access whycant needs. Implementations must be
// strictly read-only: nothing here may change the system.
type System interface {
	// Lstat describes path without following a final symlink. For symlinks,
	// FileInfo.LinkTarget is filled in.
	Lstat(path string) (FileInfo, error)
	Readlink(path string) (string, error)
	// Getxattr returns the raw value of an extended attribute, or an error
	// wrapping ErrNoAttr when it is not set.
	Getxattr(path, name string) ([]byte, error)
	// InodeFlags returns FS_IOC_GETFLAGS for a regular file or directory, or
	// an error wrapping ErrNotSupported when the filesystem has no flags.
	InodeFlags(path string) (uint32, error)
	Statfs(path string) (FSStats, error)
	// ReadFile reads a whole file; meant for /proc, /sys and config files.
	ReadFile(path string) ([]byte, error)
	// ReadDirNames lists the names in a directory.
	ReadDirNames(path string) ([]string, error)
	// ReadHead reads at most n bytes from the start of a regular file.
	ReadHead(path string, n int) ([]byte, error)
	// Run executes a read-only helper command (getent, id, journalctl...)
	// and returns its stdout. A missing binary wraps ErrCommandNotFound.
	Run(name string, args ...string) ([]byte, error)
	Getgroups() ([]uint32, error)
	Getuid() uint32
	Getgid() uint32
	// Getwd returns the working directory, to make relative paths absolute.
	Getwd() (string, error)
	// Machine is the host architecture as a GOARCH value, e.g. "amd64".
	Machine() string
	Getenv(key string) string
	// Terminal reports whether stdout is a terminal, and its width in
	// columns (0 if unknown).
	Terminal() (tty bool, width int)

	// Access is access(2): it checks path against the calling process's
	// real uid and gid. Only the --verify probe uses it.
	Access(path string, mode uint32) error
	// Probe re-runs this whycant binary with args under cred, for --verify.
	// It returns the exit code and anything printed to stderr.
	Probe(cred Credential, args ...string) (code int, stderr string, err error)
}

// Credential is the identity a --verify probe runs as.
type Credential struct {
	UID    uint32
	GID    uint32
	Groups []uint32
}

// Modes for Access.
const (
	AccessR uint32 = 4
	AccessW uint32 = 2
	AccessX uint32 = 1
)

// Sentinel errors returned (wrapped) by System implementations. Permission
// and existence errors are reported as syscall errnos, which match
// fs.ErrPermission and fs.ErrNotExist via errors.Is.
var (
	ErrNoAttr          = errors.New("attribute not set")
	ErrNotSupported    = errors.New("not supported by this filesystem")
	ErrCommandNotFound = errors.New("command not found")
)

// File type and special bits of st_mode, as defined by Linux.
const (
	ModeType    uint32 = 0o170000
	TypeSocket  uint32 = 0o140000
	TypeSymlink uint32 = 0o120000
	TypeRegular uint32 = 0o100000
	TypeBlock   uint32 = 0o060000
	TypeDir     uint32 = 0o040000
	TypeChar    uint32 = 0o020000
	TypeFIFO    uint32 = 0o010000

	ModeSetuid uint32 = 0o4000
	ModeSetgid uint32 = 0o2000
	ModeSticky uint32 = 0o1000
	ModePerm   uint32 = 0o777
)

// Inode flags from FS_IOC_GETFLAGS that matter for access decisions.
const (
	FlagImmutable  uint32 = 0x00000010
	FlagAppendOnly uint32 = 0x00000020
)

// FileInfo is the subset of struct stat whycant uses.
type FileInfo struct {
	Mode       uint32 // raw st_mode: type | special | permission bits
	UID        uint32
	GID        uint32
	Ino        uint64
	Dev        uint64
	Nlink      uint64
	Size       int64
	LinkTarget string // only for symlinks
}

// Type returns the file type bits.
func (fi FileInfo) Type() uint32 { return fi.Mode & ModeType }

// IsDir reports whether fi describes a directory.
func (fi FileInfo) IsDir() bool { return fi.Type() == TypeDir }

// IsRegular reports whether fi describes a regular file.
func (fi FileInfo) IsRegular() bool { return fi.Type() == TypeRegular }

// IsSymlink reports whether fi describes a symbolic link.
func (fi FileInfo) IsSymlink() bool { return fi.Type() == TypeSymlink }

// Perm returns the rwxrwxrwx bits.
func (fi FileInfo) Perm() uint32 { return fi.Mode & ModePerm }

// ModeString formats the mode like ls -l, e.g. "drwxr-sr-t".
func (fi FileInfo) ModeString() string {
	var b [10]byte
	switch fi.Type() {
	case TypeDir:
		b[0] = 'd'
	case TypeSymlink:
		b[0] = 'l'
	case TypeChar:
		b[0] = 'c'
	case TypeBlock:
		b[0] = 'b'
	case TypeFIFO:
		b[0] = 'p'
	case TypeSocket:
		b[0] = 's'
	default:
		b[0] = '-'
	}
	const rwx = "rwxrwxrwx"
	for i := range 9 {
		if fi.Mode&(1<<(8-i)) != 0 {
			b[i+1] = rwx[i]
		} else {
			b[i+1] = '-'
		}
	}
	special := func(pos int, set bool, lower, upper byte) {
		if !set {
			return
		}
		if b[pos] == '-' {
			b[pos] = upper
		} else {
			b[pos] = lower
		}
	}
	special(3, fi.Mode&ModeSetuid != 0, 's', 'S')
	special(6, fi.Mode&ModeSetgid != 0, 's', 'S')
	special(9, fi.Mode&ModeSticky != 0, 't', 'T')
	return string(b[:])
}

// FSStats is the subset of struct statfs whycant uses.
type FSStats struct {
	Type   int64
	Bsize  int64
	Blocks uint64
	Bfree  uint64
	Bavail uint64
	Files  uint64
	Ffree  uint64
}
