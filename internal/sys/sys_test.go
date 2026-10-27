package sys

import (
	"errors"
	"io/fs"
	"syscall"
	"testing"
)

func TestModeString(t *testing.T) {
	tests := []struct {
		mode uint32
		want string
	}{
		{TypeDir | 0o750, "drwxr-x---"},
		{TypeRegular | 0o644, "-rw-r--r--"},
		{TypeDir | ModeSticky | 0o777, "drwxrwxrwt"},
		{TypeDir | ModeSticky | 0o770, "drwxrwx--T"},
		{TypeRegular | ModeSetuid | 0o755, "-rwsr-xr-x"},
		{TypeRegular | ModeSetuid | 0o644, "-rwSr--r--"},
		{TypeDir | ModeSetgid | 0o2775, "drwxrwsr-x"},
		{TypeSymlink | 0o777, "lrwxrwxrwx"},
		{TypeFIFO | 0o600, "prw-------"},
		{TypeRegular | 0o047, "----r--rwx"},
	}
	for _, tt := range tests {
		if got := (FileInfo{Mode: tt.mode}).ModeString(); got != tt.want {
			t.Errorf("ModeString(%o) = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestFakeTree(t *testing.T) {
	f := NewFake()
	f.File("/srv/app/config/db.yml", 0o640, 1000, 1000, "secret: 1\n")
	f.Dir("/srv/app", 0o750, 1000, 1000)
	f.Symlink("/srv/current", "app", 0, 0)

	fi, err := f.Lstat("/srv/app")
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Perm() != 0o750 || fi.UID != 1000 {
		t.Errorf("/srv/app = %+v", fi)
	}

	// Missing parents are created as root-owned 0755 directories.
	fi, err = f.Lstat("/srv/app/config")
	if err != nil || !fi.IsDir() || fi.Perm() != 0o755 || fi.UID != 0 {
		t.Errorf("/srv/app/config = %+v, %v", fi, err)
	}

	fi, err = f.Lstat("/srv/current")
	if err != nil || !fi.IsSymlink() || fi.LinkTarget != "app" {
		t.Errorf("/srv/current = %+v, %v", fi, err)
	}

	head, err := f.ReadHead("/srv/app/config/db.yml", 6)
	if err != nil || string(head) != "secret" {
		t.Errorf("ReadHead = %q, %v", head, err)
	}

	if _, err := f.Lstat("/nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Lstat missing: %v, want ErrNotExist", err)
	}
}

func TestFakeErrors(t *testing.T) {
	f := NewFake()
	f.Dir("/secret", 0o700, 0, 0).Err = syscall.EACCES
	f.File("/plain", 0o644, 0, 0, "")

	if _, err := f.Lstat("/secret"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("Lstat: %v, want ErrPermission", err)
	}
	if _, err := f.Getxattr("/plain", "system.posix_acl_access"); !errors.Is(err, ErrNoAttr) {
		t.Errorf("Getxattr: %v, want ErrNoAttr", err)
	}
	if _, err := f.Run("getent", "passwd", "nobody"); !errors.Is(err, ErrCommandNotFound) {
		t.Errorf("Run: %v, want ErrCommandNotFound", err)
	}

	f.SetCommand("nobody:x:65534:65534::/:/sbin/nologin\n", nil, "getent", "passwd", "nobody")
	out, err := f.Run("getent", "passwd", "nobody")
	if err != nil || string(out) == "" {
		t.Errorf("Run recorded: %q, %v", out, err)
	}
}

func TestFakeStatfsLongestPrefix(t *testing.T) {
	f := NewFake()
	f.Dir("/mnt/data/x", 0o755, 0, 0)
	f.FS["/"] = FSStats{Type: 1}
	f.FS["/mnt/data"] = FSStats{Type: 2}
	f.FS["/mnt/dat"] = FSStats{Type: 3}

	st, err := f.Statfs("/mnt/data/x")
	if err != nil || st.Type != 2 {
		t.Errorf("Statfs = %+v, %v; want type 2", st, err)
	}
}
