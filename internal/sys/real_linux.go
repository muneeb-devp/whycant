//go:build linux

package sys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// commandTimeout bounds helper commands such as journalctl, which can be slow
// on large journals.
const commandTimeout = 10 * time.Second

// Real implements System on Linux using golang.org/x/sys/unix.
type Real struct{}

var _ System = Real{}

// Lstat implements System.
func (Real) Lstat(path string) (FileInfo, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return FileInfo{}, &os.PathError{Op: "lstat", Path: path, Err: err}
	}
	fi := FileInfo{
		Mode:  st.Mode,
		UID:   st.Uid,
		GID:   st.Gid,
		Ino:   st.Ino,
		Dev:   st.Dev,
		Nlink: uint64(st.Nlink), //nolint:unconvert // Nlink is uint32 on some arches
		Size:  st.Size,
	}
	if fi.IsSymlink() {
		target, err := Real{}.Readlink(path)
		if err != nil {
			return FileInfo{}, err
		}
		fi.LinkTarget = target
	}
	return fi, nil
}

// Readlink implements System.
func (Real) Readlink(path string) (string, error) {
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		n, err := unix.Readlink(path, buf)
		if err != nil {
			return "", &os.PathError{Op: "readlink", Path: path, Err: err}
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
}

// Getxattr implements System.
func (Real) Getxattr(path, name string) ([]byte, error) {
	for {
		size, err := unix.Lgetxattr(path, name, nil)
		if err != nil {
			return nil, xattrErr(path, name, err)
		}
		buf := make([]byte, size)
		n, err := unix.Lgetxattr(path, name, buf)
		if errors.Is(err, unix.ERANGE) {
			continue // value grew between the two calls
		}
		if err != nil {
			return nil, xattrErr(path, name, err)
		}
		return buf[:n], nil
	}
}

func xattrErr(path, name string, err error) error {
	switch {
	case errors.Is(err, unix.ENODATA):
		return fmt.Errorf("getxattr %s %s: %w", path, name, ErrNoAttr)
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOTSUP):
		return fmt.Errorf("getxattr %s %s: %w", path, name, ErrNotSupported)
	}
	return &os.PathError{Op: "getxattr", Path: path, Err: err}
}

// InodeFlags implements System. It only opens regular files and directories:
// opening a device or FIFO can have side effects, which would break the
// read-only guarantee.
func (Real) InodeFlags(path string) (uint32, error) {
	fd, err := openPlain(path)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd) //nolint:errcheck // read-only fd

	flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
			return 0, fmt.Errorf("inode flags %s: %w", path, ErrNotSupported)
		}
		return 0, &os.PathError{Op: "ioctl", Path: path, Err: err}
	}
	return flags, nil
}

// Statfs implements System.
func (Real) Statfs(path string) (FSStats, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return FSStats{}, &os.PathError{Op: "statfs", Path: path, Err: err}
	}
	return FSStats{
		Type:   int64(st.Type),  //nolint:unconvert // width differs per arch
		Bsize:  int64(st.Bsize), //nolint:unconvert // width differs per arch
		Blocks: st.Blocks,
		Bfree:  st.Bfree,
		Bavail: st.Bavail,
		Files:  st.Files,
		Ffree:  st.Ffree,
	}, nil
}

// ReadFile implements System.
func (Real) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // reading arbitrary paths is the point
}

// ReadDirNames implements System.
func (Real) ReadDirNames(path string) ([]string, error) {
	fd, err := openPlain(path)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close() //nolint:errcheck // read-only file
	return f.Readdirnames(-1)
}

// ReadHead implements System.
func (Real) ReadHead(path string, n int) ([]byte, error) {
	fd, err := openPlain(path)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close() //nolint:errcheck // read-only file

	buf := make([]byte, n)
	got, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return buf[:got], nil
}

// openPlain opens a regular file or directory read-only without following a
// final symlink, refusing anything else. O_NONBLOCK keeps a FIFO swapped in
// after the type check from blocking us; the fstat recheck then rejects it.
func openPlain(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd) //nolint:errcheck,gosec // already failing
		return -1, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if t := st.Mode & unix.S_IFMT; t != unix.S_IFREG && t != unix.S_IFDIR {
		unix.Close(fd) //nolint:errcheck,gosec // already failing
		return -1, fmt.Errorf("open %s: not a regular file or directory: %w", path, ErrNotSupported)
	}
	return fd, nil
}

// Run implements System. Output is forced to the C locale so parsers see
// stable text.
func (Real) Run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // callers pass fixed, read-only commands
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w", name, ErrCommandNotFound)
		}
		return stdout.Bytes(), fmt.Errorf("%s: %w: %s", name, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

// Getgroups implements System.
func (Real) Getgroups() ([]uint32, error) {
	gids, err := unix.Getgroups()
	if err != nil {
		return nil, err
	}
	out := make([]uint32, len(gids))
	for i, g := range gids {
		out[i] = uint32(g) //nolint:gosec // gids are non-negative
	}
	return out, nil
}

// Getuid implements System.
func (Real) Getuid() uint32 {
	return uint32(unix.Getuid()) //nolint:gosec // uids are non-negative
}

// Getgid implements System.
func (Real) Getgid() uint32 {
	return uint32(unix.Getgid()) //nolint:gosec // gids are non-negative
}

// Getwd implements System.
func (Real) Getwd() (string, error) { return os.Getwd() }

// Machine implements System.
func (Real) Machine() string { return runtime.GOARCH }

// Getenv implements System.
func (Real) Getenv(key string) string { return os.Getenv(key) }

// Terminal implements System.
func (Real) Terminal() (bool, int) {
	if _, err := unix.IoctlGetTermios(1, unix.TCGETS); err != nil {
		return false, 0
	}
	ws, err := unix.IoctlGetWinsize(1, unix.TIOCGWINSZ)
	if err != nil {
		return true, 0
	}
	return true, int(ws.Col)
}

// Access implements System. With flags 0, faccessat checks the real uid and
// gid, which in the probe process are the subject's. (x/sys emulates
// AT_EACCESS in userspace on kernels without faccessat2, ignoring ACLs, so
// it is deliberately not used.)
func (Real) Access(path string, mode uint32) error {
	if err := unix.Faccessat(unix.AT_FDCWD, path, mode, 0); err != nil {
		return &os.PathError{Op: "access", Path: path, Err: err}
	}
	return nil
}

// Probe implements System.
func (Real) Probe(cred Credential, args ...string) (int, string, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, "", fmt.Errorf("finding the whycant binary: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, args...) //nolint:gosec // re-running ourselves
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: cred.UID, Gid: cred.GID, Groups: cred.Groups, NoSetGroups: false},
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), strings.TrimSpace(stderr.String()), nil
	}
	if err != nil {
		return 0, strings.TrimSpace(stderr.String()), err
	}
	return 0, strings.TrimSpace(stderr.String()), nil
}
