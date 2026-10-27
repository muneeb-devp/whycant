package identity

import (
	"errors"
	"reflect"
	"strings"
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
	want := &core.Subject{Name: "alice", UID: 1000, GID: 1000, Groups: []uint32{1000, 27}, Source: "session", Current: true, StaleGroups: []uint32{1001}}
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

func TestStale(t *testing.T) {
	got := Stale([]uint32{1000, 1001, 1002, 1001}, []uint32{1002, 1000})
	if len(got) != 1 || got[0] != 1001 {
		t.Errorf("Stale = %v", got)
	}
	if got := Stale([]uint32{1}, []uint32{1}); got != nil {
		t.Errorf("Stale = %v, want nil", got)
	}
}

const nginxStatus = `Name:	nginx
Umask:	0022
State:	S (sleeping)
Pid:	812
Uid:	33	33	33	33
Gid:	33	33	33	33
Groups:	33 
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
`

func TestFromPID(t *testing.T) {
	f := filesWorld()
	f.File("/proc/812/status", 0o444, 0, 0, nginxStatus)
	f.File("/proc/812/attr/current", 0o444, 0, 0, "nginx (enforce)\n")
	// www-data was added to "web" (1002) after nginx started.
	s, err := NewResolver(f).FromPID(812)
	if err != nil {
		t.Fatal(err)
	}
	want := &core.Subject{
		Name: "www-data", UID: 33, GID: 33, Groups: []uint32{33}, Source: "pid:812",
		Label: "nginx (enforce)", StaleGroups: []uint32{1002}, PID: 812, Process: "nginx",
	}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("FromPID = %+v\nwant %+v", s, want)
	}
	if got := s.Display(); got != "nginx (pid 812, www-data, uid 33)" {
		t.Errorf("Display = %q", got)
	}

	root := strings.ReplaceAll(nginxStatus, "33", "0")
	root = strings.ReplaceAll(root, "CapEff:\t0000000000000000", "CapEff:\t000001ffffffffff")
	f.File("/proc/1/status", 0o444, 0, 0, root)
	s, err = NewResolver(f).FromPID(1)
	if err != nil || !s.Caps.Has(core.CapDACOverride) || s.UID != 0 {
		t.Errorf("root process = %+v, %v", s, err)
	}

	if _, err := NewResolver(f).FromPID(4242); err == nil || !strings.Contains(err.Error(), "no process") {
		t.Errorf("missing pid: %v", err)
	}
}
