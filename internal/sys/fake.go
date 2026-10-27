package sys

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"syscall"
)

// Fake is an in-memory System for tests. Build a tree with Dir, File and
// Symlink; missing parent directories are created as root:root 0755.
//
// Fake does not enforce permissions on whycant itself: set FakeFile.Err to
// simulate a component whycant cannot inspect.
type Fake struct {
	UID    uint32
	GID    uint32
	Groups []uint32
	Cwd    string // defaults to "/"

	Files    map[string]*FakeFile
	Commands map[string]FakeCommand
	// FS maps a mount point to its statfs result; Statfs uses the longest
	// matching prefix.
	FS map[string]FSStats

	nextIno uint64
}

// FakeFile is one node in a Fake tree.
type FakeFile struct {
	Mode    uint32
	UID     uint32
	GID     uint32
	Ino     uint64
	Dev     uint64
	Target  string // symlink target
	Content []byte
	Xattrs  map[string][]byte
	Flags   uint32
	// FlagsErr is returned by InodeFlags, e.g. to simulate ErrNotSupported.
	FlagsErr error
	// Err, when set, is returned by every call on this path, e.g.
	// syscall.EACCES to simulate a component whycant cannot inspect.
	Err error
}

// FakeCommand is the recorded result of a helper command.
type FakeCommand struct {
	Output []byte
	Err    error
}

var _ System = (*Fake)(nil)

// NewFake returns a Fake containing only "/" (root:root 0755), run as uid 0.
func NewFake() *Fake {
	f := &Fake{
		Files:    map[string]*FakeFile{},
		Commands: map[string]FakeCommand{},
		FS:       map[string]FSStats{},
	}
	f.add("/", TypeDir|0o755, 0, 0)
	return f
}

// Dir adds a directory with the given permission bits (including special bits).
func (f *Fake) Dir(p string, mode, uid, gid uint32) *FakeFile {
	return f.add(p, TypeDir|mode, uid, gid)
}

// File adds a regular file.
func (f *Fake) File(p string, mode, uid, gid uint32, content string) *FakeFile {
	n := f.add(p, TypeRegular|mode, uid, gid)
	n.Content = []byte(content)
	return n
}

// Symlink adds a symbolic link pointing at target.
func (f *Fake) Symlink(p, target string, uid, gid uint32) *FakeFile {
	n := f.add(p, TypeSymlink|0o777, uid, gid)
	n.Target = target
	return n
}

// SetCommand records the output of name with args.
func (f *Fake) SetCommand(output string, err error, name string, args ...string) {
	f.Commands[commandKey(name, args)] = FakeCommand{Output: []byte(output), Err: err}
}

func (f *Fake) add(p string, mode, uid, gid uint32) *FakeFile {
	p = path.Clean(p)
	if dir := path.Dir(p); p != "/" && f.Files[dir] == nil {
		f.add(dir, TypeDir|0o755, 0, 0)
	}
	f.nextIno++
	n := &FakeFile{Mode: mode, UID: uid, GID: gid, Ino: f.nextIno, Dev: 1}
	f.Files[p] = n
	return n
}

func (f *Fake) lookup(op, p string) (*FakeFile, error) {
	n := f.Files[path.Clean(p)]
	if n == nil {
		return nil, &fs.PathError{Op: op, Path: p, Err: syscall.ENOENT}
	}
	if n.Err != nil {
		return nil, &fs.PathError{Op: op, Path: p, Err: n.Err}
	}
	return n, nil
}

// Lstat implements System.
func (f *Fake) Lstat(p string) (FileInfo, error) {
	n, err := f.lookup("lstat", p)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Mode:       n.Mode,
		UID:        n.UID,
		GID:        n.GID,
		Ino:        n.Ino,
		Dev:        n.Dev,
		Nlink:      1,
		Size:       int64(len(n.Content)),
		LinkTarget: n.Target,
	}, nil
}

// Readlink implements System.
func (f *Fake) Readlink(p string) (string, error) {
	n, err := f.lookup("readlink", p)
	if err != nil {
		return "", err
	}
	if n.Mode&ModeType != TypeSymlink {
		return "", &fs.PathError{Op: "readlink", Path: p, Err: syscall.EINVAL}
	}
	return n.Target, nil
}

// Getxattr implements System.
func (f *Fake) Getxattr(p, name string) ([]byte, error) {
	n, err := f.lookup("getxattr", p)
	if err != nil {
		return nil, err
	}
	v, ok := n.Xattrs[name]
	if !ok {
		return nil, fmt.Errorf("getxattr %s %s: %w", p, name, ErrNoAttr)
	}
	return v, nil
}

// InodeFlags implements System.
func (f *Fake) InodeFlags(p string) (uint32, error) {
	n, err := f.lookup("ioctl", p)
	if err != nil {
		return 0, err
	}
	if t := n.Mode & ModeType; t != TypeRegular && t != TypeDir {
		return 0, fmt.Errorf("inode flags %s: %w", p, ErrNotSupported)
	}
	if n.FlagsErr != nil {
		return 0, n.FlagsErr
	}
	return n.Flags, nil
}

// Statfs implements System.
func (f *Fake) Statfs(p string) (FSStats, error) {
	if _, err := f.lookup("statfs", p); err != nil {
		return FSStats{}, err
	}
	best := ""
	for mp := range f.FS {
		if hasPathPrefix(p, mp) && len(mp) > len(best) {
			best = mp
		}
	}
	if best == "" {
		return FSStats{}, fmt.Errorf("statfs %s: %w", p, ErrNotSupported)
	}
	return f.FS[best], nil
}

// ReadFile implements System.
func (f *Fake) ReadFile(p string) ([]byte, error) {
	n, err := f.lookup("open", p)
	if err != nil {
		return nil, err
	}
	if n.Mode&ModeType == TypeDir {
		return nil, &fs.PathError{Op: "read", Path: p, Err: syscall.EISDIR}
	}
	return n.Content, nil
}

// ReadDirNames implements System.
func (f *Fake) ReadDirNames(p string) ([]string, error) {
	n, err := f.lookup("open", p)
	if err != nil {
		return nil, err
	}
	if n.Mode&ModeType != TypeDir {
		return nil, &fs.PathError{Op: "readdir", Path: p, Err: syscall.ENOTDIR}
	}
	p = path.Clean(p)
	var names []string
	for child := range f.Files {
		if child != p && path.Dir(child) == p {
			names = append(names, path.Base(child))
		}
	}
	sort.Strings(names)
	return names, nil
}

// ReadHead implements System.
func (f *Fake) ReadHead(p string, max int) ([]byte, error) {
	n, err := f.lookup("open", p)
	if err != nil {
		return nil, err
	}
	if n.Mode&ModeType != TypeRegular {
		return nil, fmt.Errorf("open %s: not a regular file: %w", p, ErrNotSupported)
	}
	return n.Content[:min(max, len(n.Content))], nil
}

// Run implements System. Unrecorded commands behave as if not installed.
func (f *Fake) Run(name string, args ...string) ([]byte, error) {
	c, ok := f.Commands[commandKey(name, args)]
	if !ok {
		return nil, fmt.Errorf("%s: %w", name, ErrCommandNotFound)
	}
	return c.Output, c.Err
}

// Getgroups implements System.
func (f *Fake) Getgroups() ([]uint32, error) { return f.Groups, nil }

// Getuid implements System.
func (f *Fake) Getuid() uint32 { return f.UID }

// Getgid implements System.
func (f *Fake) Getgid() uint32 { return f.GID }

// Getwd implements System.
func (f *Fake) Getwd() (string, error) {
	if f.Cwd == "" {
		return "/", nil
	}
	return f.Cwd, nil
}

func commandKey(name string, args []string) string {
	return strings.Join(append([]string{name}, args...), "\x00")
}

// hasPathPrefix reports whether p is prefix or lies below it.
func hasPathPrefix(p, prefix string) bool {
	if prefix == "/" || p == prefix {
		return true
	}
	return strings.HasPrefix(p, prefix+"/")
}
