//go:build linux

package sys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRealBasics(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("#!/bin/sh\necho hi\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "l")
	if err := os.Symlink("f", link); err != nil {
		t.Fatal(err)
	}

	var r Real
	fi, err := r.Lstat(file)
	if err != nil || !fi.IsRegular() || fi.Perm() != 0o640 {
		t.Errorf("Lstat file = %+v, %v", fi, err)
	}
	fi, err = r.Lstat(link)
	if err != nil || !fi.IsSymlink() || fi.LinkTarget != "f" {
		t.Errorf("Lstat link = %+v, %v", fi, err)
	}
	head, err := r.ReadHead(file, 2)
	if err != nil || string(head) != "#!" {
		t.Errorf("ReadHead = %q, %v", head, err)
	}
	if _, err := r.ReadHead(link, 2); err == nil {
		t.Error("ReadHead followed a symlink")
	}
	if _, err := r.Getxattr(file, "user.whycant-test-unset"); err != nil &&
		!errors.Is(err, ErrNoAttr) && !errors.Is(err, ErrNotSupported) {
		t.Errorf("Getxattr unset: %v", err)
	}
	if _, err := r.InodeFlags(file); err != nil && !errors.Is(err, ErrNotSupported) {
		t.Errorf("InodeFlags: %v", err)
	}
	if _, err := r.Run("whycant-no-such-command"); !errors.Is(err, ErrCommandNotFound) {
		t.Errorf("Run missing: %v", err)
	}
	if _, err := r.Statfs(dir); err != nil {
		t.Errorf("Statfs: %v", err)
	}
}
