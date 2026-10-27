// Package acl parses POSIX ACLs from the binary form the kernel stores in
// the system.posix_acl_access and system.posix_acl_default xattrs.
package acl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Xattr names.
const (
	XattrAccess  = "system.posix_acl_access"
	XattrDefault = "system.posix_acl_default"
)

// Entry tags.
const (
	TagUserObj  uint16 = 0x01
	TagUser     uint16 = 0x02
	TagGroupObj uint16 = 0x04
	TagGroup    uint16 = 0x08
	TagMask     uint16 = 0x10
	TagOther    uint16 = 0x20
)

const (
	version   = 2
	headerLen = 4
	entryLen  = 8
)

// Entry is one ACL entry. ID is only meaningful for TagUser and TagGroup.
type Entry struct {
	Tag  uint16
	Perm uint16 // rwx bits: 4, 2, 1
	ID   uint32
}

// ACL is a parsed access or default ACL, entries in kernel order.
type ACL struct {
	Entries []Entry
}

// Parse decodes the xattr value: a little-endian u32 version (2) followed by
// 8-byte entries of tag u16, perm u16, id u32.
func Parse(b []byte) (*ACL, error) {
	if len(b) < headerLen {
		return nil, errors.New("acl: too short")
	}
	if v := binary.LittleEndian.Uint32(b); v != version {
		return nil, fmt.Errorf("acl: unsupported version %d", v)
	}
	body := b[headerLen:]
	if len(body)%entryLen != 0 {
		return nil, fmt.Errorf("acl: %d trailing bytes", len(body)%entryLen)
	}
	a := &ACL{Entries: make([]Entry, 0, len(body)/entryLen)}
	for i := 0; i < len(body); i += entryLen {
		e := Entry{
			Tag:  binary.LittleEndian.Uint16(body[i:]),
			Perm: binary.LittleEndian.Uint16(body[i+2:]),
			ID:   binary.LittleEndian.Uint32(body[i+4:]),
		}
		switch e.Tag {
		case TagUserObj, TagUser, TagGroupObj, TagGroup, TagMask, TagOther:
		default:
			return nil, fmt.Errorf("acl: unknown tag %#x", e.Tag)
		}
		if e.Perm&^7 != 0 {
			return nil, fmt.Errorf("acl: invalid permission bits %#x", e.Perm)
		}
		a.Entries = append(a.Entries, e)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return a, nil
}

// validate enforces the kernel's rules: exactly one USER_OBJ, GROUP_OBJ and
// OTHER; a MASK when there are named entries; no duplicate named entries.
func (a *ACL) validate() error {
	counts := map[uint16]int{}
	seen := map[[2]uint32]bool{}
	for _, e := range a.Entries {
		counts[e.Tag]++
		if e.Tag == TagUser || e.Tag == TagGroup {
			key := [2]uint32{uint32(e.Tag), e.ID}
			if seen[key] {
				return fmt.Errorf("acl: duplicate entry for id %d", e.ID)
			}
			seen[key] = true
		}
	}
	for _, tag := range []uint16{TagUserObj, TagGroupObj, TagOther} {
		if counts[tag] != 1 {
			return errors.New("acl: missing or repeated base entry")
		}
	}
	if counts[TagMask] > 1 || (counts[TagUser]+counts[TagGroup] > 0 && counts[TagMask] == 0) {
		return errors.New("acl: invalid mask entry")
	}
	return nil
}

// Encode is the inverse of Parse.
func (a *ACL) Encode() []byte {
	b := make([]byte, headerLen+entryLen*len(a.Entries))
	binary.LittleEndian.PutUint32(b, version)
	for i, e := range a.Entries {
		off := headerLen + i*entryLen
		binary.LittleEndian.PutUint16(b[off:], e.Tag)
		binary.LittleEndian.PutUint16(b[off+2:], e.Perm)
		binary.LittleEndian.PutUint32(b[off+4:], e.ID)
	}
	return b
}

// Extended reports whether the ACL holds more than the three entries that
// the mode bits already express.
func (a *ACL) Extended() bool {
	for _, e := range a.Entries {
		if e.Tag == TagUser || e.Tag == TagGroup || e.Tag == TagMask {
			return true
		}
	}
	return false
}

// Find returns the first entry with tag (and id, for named entries).
func (a *ACL) Find(tag uint16, id uint32) (Entry, bool) {
	for _, e := range a.Entries {
		if e.Tag == tag && (tag != TagUser && tag != TagGroup || e.ID == id) {
			return e, true
		}
	}
	return Entry{}, false
}

// Mask returns the mask permission, or rwx when there is no mask entry.
func (a *ACL) Mask() (perm uint16, ok bool) {
	if e, ok := a.Find(TagMask, 0); ok {
		return e.Perm, true
	}
	return 7, false
}

// Format renders the ACL like getfacl's short form, e.g.
// "user::rw-,user:33:r--,group::r--,mask::r--,other::---". names maps ids to
// names for named entries; missing ids are shown as numbers.
func (a *ACL) Format(userName, groupName func(uint32) string) string {
	entries := append([]Entry(nil), a.Entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Tag < entries[j].Tag })
	parts := make([]string, len(entries))
	for i, e := range entries {
		var who string
		switch e.Tag {
		case TagUserObj:
			who = "user:"
		case TagUser:
			who = "user:" + nameOr(userName, e.ID)
		case TagGroupObj:
			who = "group:"
		case TagGroup:
			who = "group:" + nameOr(groupName, e.ID)
		case TagMask:
			who = "mask:"
		case TagOther:
			who = "other:"
		}
		parts[i] = who + ":" + PermString(e.Perm)
	}
	return strings.Join(parts, ",")
}

func nameOr(f func(uint32) string, id uint32) string {
	if f != nil {
		return f(id)
	}
	return strconv.FormatUint(uint64(id), 10)
}

// PermString formats rwx bits as "r-x".
func PermString(p uint16) string {
	b := []byte("---")
	if p&4 != 0 {
		b[0] = 'r'
	}
	if p&2 != 0 {
		b[1] = 'w'
	}
	if p&1 != 0 {
		b[2] = 'x'
	}
	return string(b)
}
