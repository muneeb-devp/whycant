package acl

import (
	"bytes"
	"testing"
)

func sample() *ACL {
	return &ACL{Entries: []Entry{
		{Tag: TagUserObj, Perm: 6},
		{Tag: TagUser, Perm: 6, ID: 33},
		{Tag: TagGroupObj, Perm: 4},
		{Tag: TagGroup, Perm: 5, ID: 1001},
		{Tag: TagMask, Perm: 4},
		{Tag: TagOther, Perm: 0},
	}}
}

func TestRoundTrip(t *testing.T) {
	b := sample().Encode()
	a, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Encode(), b) {
		t.Error("round trip changed bytes")
	}
	if !a.Extended() {
		t.Error("Extended() = false")
	}
	if m, ok := a.Mask(); !ok || m != 4 {
		t.Errorf("Mask() = %d, %v", m, ok)
	}
	if e, ok := a.Find(TagUser, 33); !ok || e.Perm != 6 {
		t.Errorf("Find(user 33) = %+v, %v", e, ok)
	}
	if _, ok := a.Find(TagUser, 34); ok {
		t.Error("Find(user 34) found an entry")
	}
	names := func(id uint32) string { return map[uint32]string{33: "www-data", 1001: "deploy"}[id] }
	want := "user::rw-,user:www-data:rw-,group::r--,group:deploy:r-x,mask::r--,other::---"
	if got := a.Format(names, names); got != want {
		t.Errorf("Format = %q, want %q", got, want)
	}
}

func TestMinimalACL(t *testing.T) {
	a, err := Parse((&ACL{Entries: []Entry{
		{Tag: TagUserObj, Perm: 7}, {Tag: TagGroupObj, Perm: 5}, {Tag: TagOther, Perm: 5},
	}}).Encode())
	if err != nil {
		t.Fatal(err)
	}
	if a.Extended() {
		t.Error("minimal ACL reported as extended")
	}
	if m, ok := a.Mask(); ok || m != 7 {
		t.Errorf("Mask() = %d, %v", m, ok)
	}
}

func TestParseMalformed(t *testing.T) {
	good := sample().Encode()
	bad := map[string][]byte{
		"empty":         nil,
		"short header":  {2, 0},
		"bad version":   append([]byte{1, 0, 0, 0}, good[4:]...),
		"trailing":      append(append([]byte{}, good...), 1, 2, 3),
		"unknown tag":   (&ACL{Entries: []Entry{{Tag: 0x40}}}).Encode(),
		"bad perm":      (&ACL{Entries: []Entry{{Tag: TagUserObj, Perm: 8}, {Tag: TagGroupObj}, {Tag: TagOther}}}).Encode(),
		"no other":      (&ACL{Entries: []Entry{{Tag: TagUserObj}, {Tag: TagGroupObj}}}).Encode(),
		"named no mask": (&ACL{Entries: []Entry{{Tag: TagUserObj}, {Tag: TagUser, ID: 1}, {Tag: TagGroupObj}, {Tag: TagOther}}}).Encode(),
		"duplicate": (&ACL{Entries: []Entry{
			{Tag: TagUserObj}, {Tag: TagUser, ID: 1}, {Tag: TagUser, ID: 1}, {Tag: TagGroupObj}, {Tag: TagMask}, {Tag: TagOther},
		}}).Encode(),
	}
	for name, b := range bad {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: Parse succeeded", name)
		}
	}
}

func FuzzParseACL(f *testing.F) {
	f.Add(sample().Encode())
	f.Add([]byte{2, 0, 0, 0})
	f.Add([]byte{2, 0, 0, 0, 1, 0, 7, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := Parse(b)
		if err != nil {
			return
		}
		if !bytes.Equal(a.Encode(), b) {
			t.Errorf("round trip mismatch for %x", b)
		}
		_ = a.Format(nil, nil)
	})
}
