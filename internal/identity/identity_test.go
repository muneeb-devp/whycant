package identity

import (
	"errors"
	"reflect"
	"testing"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

const passwd = `root:x:0:0:root:/root:/bin/bash
# comment
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
alice:x:1000:1000::/home/alice:/bin/bash
`

const group = `root:x:0:
www-data:x:33:
alice:x:1000:
deploy:x:1001:alice,bob
web:x:1002:www-data
`

func filesWorld() *sys.Fake {
	f := sys.NewFake()
	f.File("/etc/passwd", 0o644, 0, 0, passwd)
	f.File("/etc/group", 0o644, 0, 0, group)
	return f
}

func TestSubjectFromFiles(t *testing.T) {
	r := NewResolver(filesWorld())
	s, err := r.Subject("alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := &core.Subject{Name: "alice", UID: 1000, GID: 1000, Groups: []uint32{1000, 1001}, Source: "files"}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("Subject = %+v, want %+v", s, want)
	}

	s, err = r.Subject("33", []string{"deploy", "4242"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "www-data" || !reflect.DeepEqual(s.Groups, []uint32{33, 1002, 1001, 4242}) {
		t.Errorf("Subject(33) = %+v", s)
	}

	root, err := r.Subject("root", nil)
	if err != nil || root.Caps != core.AllCaps {
		t.Errorf("root caps = %v, %v", root.Caps, err)
	}
}

func TestSubjectFromNSS(t *testing.T) {
	f := sys.NewFake() // no /etc files: NSS must be used
	f.SetCommand("carol:x:5000:5000:Carol:/home/carol:/bin/zsh\n", nil, "getent", "passwd", "carol")
	f.SetCommand("5000 5001 5002\n", nil, "id", "-G", "carol")
	r := NewResolver(f)

	s, err := r.Subject("carol", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Source != "nss" || s.UID != 5000 || !reflect.DeepEqual(s.Groups, []uint32{5000, 5001, 5002}) {
		t.Errorf("Subject = %+v", s)
	}
}

func TestSubjectNotFound(t *testing.T) {
	f := filesWorld()
	if _, err := NewResolver(f).Subject("mallory", nil); err == nil {
		t.Error("expected error for unknown user")
	}
	if _, err := NewResolver(f).Subject("alice", []string{"nogroup"}); err == nil {
		t.Error("expected error for unknown group")
	}

	// getent present but the key is unknown: it exits non-zero.
	n := sys.NewFake()
	n.SetCommand("", errors.New("exit status 2"), "getent", "passwd", "mallory")
	if _, err := NewResolver(n).Subject("mallory", nil); err == nil {
		t.Error("expected error for unknown NSS user")
	}
}

func TestCurrentSubject(t *testing.T) {
	f := filesWorld()
	f.UID, f.GID, f.Groups = 1000, 1000, []uint32{1000, 27}
	s, err := NewResolver(f).Subject("", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := &core.Subject{Name: "alice", UID: 1000, GID: 1000, Groups: []uint32{1000, 27}, Source: "session", Current: true}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("Subject = %+v, want %+v", s, want)
	}

	// A uid without a passwd entry (common in containers) still works.
	f.UID = 4321
	s, err = NewResolver(f).Subject("", nil)
	if err != nil || s.Name != "" || s.Display() != "uid 4321" {
		t.Errorf("Subject = %+v, %v", s, err)
	}
}

func TestNames(t *testing.T) {
	r := NewResolver(filesWorld())
	if got := r.UserName(33); got != "www-data" {
		t.Errorf("UserName(33) = %q", got)
	}
	if got := r.UserName(777); got != "777" {
		t.Errorf("UserName(777) = %q", got)
	}
	if got := r.GroupName(1001); got != "deploy" {
		t.Errorf("GroupName(1001) = %q", got)
	}
	if got := r.GroupName(888); got != "888" {
		t.Errorf("GroupName(888) = %q", got)
	}
}
