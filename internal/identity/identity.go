// Package identity resolves the subject whose access is checked, and turns
// uids and gids into names.
//
// Lookups go through NSS first (getent, id) so LDAP, SSSD and NIS users are
// found even in a static binary, and fall back to /etc/passwd and /etc/group.
package identity

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// ErrNotFound means no passwd or group entry matched.
var ErrNotFound = errors.New("not found")

// Resolver looks up users and groups, caching names.
type Resolver struct {
	sys        sys.System
	userNames  map[uint32]string
	groupNames map[uint32]string
}

// NewResolver returns a Resolver backed by s.
func NewResolver(s sys.System) *Resolver {
	return &Resolver{sys: s, userNames: map[uint32]string{}, groupNames: map[uint32]string{}}
}

type userEntry struct {
	Name     string
	UID, GID uint32
}

type groupEntry struct {
	Name    string
	GID     uint32
	Members []string
}

// Subject builds the subject for spec (a user name or uid; empty for the
// user running whycant) plus any extra groups (names or gids).
func (r *Resolver) Subject(spec string, extraGroups []string) (*core.Subject, error) {
	s := &core.Subject{}
	if spec == "" {
		s.UID = r.sys.Getuid()
		s.GID = r.sys.Getgid()
		groups, err := r.sys.Getgroups()
		if err != nil {
			return nil, fmt.Errorf("reading session groups: %w", err)
		}
		s.Groups = dedupe(append([]uint32{s.GID}, groups...))
		s.Source = "session"
		s.Current = true
		if u, _, err := r.lookupUser(strconv.FormatUint(uint64(s.UID), 10)); err == nil {
			s.Name = u.Name
		}
	} else {
		u, src, err := r.lookupUser(spec)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, fmt.Errorf("no such user %q", spec)
			}
			return nil, err
		}
		groups, err := r.groupsOf(u)
		if err != nil {
			return nil, err
		}
		s.Name, s.UID, s.GID = u.Name, u.UID, u.GID
		s.Groups = dedupe(append([]uint32{u.GID}, groups...))
		s.Source = src
	}

	for _, g := range extraGroups {
		gid, err := r.resolveGroup(g)
		if err != nil {
			return nil, err
		}
		s.Groups = dedupe(append(s.Groups, gid))
	}
	if s.UID == 0 {
		s.Caps = core.AllCaps
	}
	return s, nil
}

// UserName returns the name for uid, or the number when it has none.
func (r *Resolver) UserName(uid uint32) string {
	if name, ok := r.userNames[uid]; ok {
		return name
	}
	key := strconv.FormatUint(uint64(uid), 10)
	name := key
	if u, _, err := r.lookupUser(key); err == nil {
		name = u.Name
	}
	r.userNames[uid] = name
	return name
}

// GroupName returns the name for gid, or the number when it has none.
func (r *Resolver) GroupName(gid uint32) string {
	if name, ok := r.groupNames[gid]; ok {
		return name
	}
	key := strconv.FormatUint(uint64(gid), 10)
	name := key
	if g, err := r.lookupGroup(key); err == nil {
		name = g.Name
	}
	r.groupNames[gid] = name
	return name
}

func (r *Resolver) resolveGroup(spec string) (uint32, error) {
	g, err := r.lookupGroup(spec)
	if err == nil {
		return g.GID, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return 0, err
	}
	// A bare number is a valid gid even without a group entry.
	if n, perr := strconv.ParseUint(spec, 10, 32); perr == nil {
		return uint32(n), nil
	}
	return 0, fmt.Errorf("no such group %q", spec)
}

// lookupUser finds a passwd entry by name or uid and reports the source used.
func (r *Resolver) lookupUser(key string) (userEntry, string, error) {
	out, err := r.sys.Run("getent", "passwd", key)
	if err == nil {
		if u, ok := parsePasswd(firstLine(out)); ok {
			return u, "nss", nil
		}
		return userEntry{}, "", fmt.Errorf("unexpected getent passwd output %q", out)
	}
	if !errors.Is(err, sys.ErrCommandNotFound) {
		// getent exits 2 when the key is unknown.
		return userEntry{}, "", ErrNotFound
	}
	data, err := r.sys.ReadFile("/etc/passwd")
	if err != nil {
		return userEntry{}, "", fmt.Errorf("reading /etc/passwd: %w", err)
	}
	for _, line := range lines(data) {
		if u, ok := parsePasswd(line); ok && (u.Name == key || strconv.FormatUint(uint64(u.UID), 10) == key) {
			return u, "files", nil
		}
	}
	return userEntry{}, "", ErrNotFound
}

func (r *Resolver) lookupGroup(key string) (groupEntry, error) {
	out, err := r.sys.Run("getent", "group", key)
	if err == nil {
		if g, ok := parseGroup(firstLine(out)); ok {
			return g, nil
		}
		return groupEntry{}, fmt.Errorf("unexpected getent group output %q", out)
	}
	if !errors.Is(err, sys.ErrCommandNotFound) {
		return groupEntry{}, ErrNotFound
	}
	groups, err := r.groupFile()
	if err != nil {
		return groupEntry{}, err
	}
	for _, g := range groups {
		if g.Name == key || strconv.FormatUint(uint64(g.GID), 10) == key {
			return g, nil
		}
	}
	return groupEntry{}, ErrNotFound
}

// groupsOf returns the configured groups of u, including its primary group.
func (r *Resolver) groupsOf(u userEntry) ([]uint32, error) {
	out, err := r.sys.Run("id", "-G", u.Name)
	if err == nil {
		var gids []uint32
		for _, f := range strings.Fields(string(out)) {
			n, perr := strconv.ParseUint(f, 10, 32)
			if perr != nil {
				return nil, fmt.Errorf("unexpected id -G output %q", out)
			}
			gids = append(gids, uint32(n))
		}
		return gids, nil
	}
	if !errors.Is(err, sys.ErrCommandNotFound) {
		return nil, fmt.Errorf("listing groups of %s: %w", u.Name, err)
	}
	groups, err := r.groupFile()
	if err != nil {
		return nil, err
	}
	gids := []uint32{u.GID}
	for _, g := range groups {
		for _, m := range g.Members {
			if m == u.Name {
				gids = append(gids, g.GID)
				break
			}
		}
	}
	return gids, nil
}

func (r *Resolver) groupFile() ([]groupEntry, error) {
	data, err := r.sys.ReadFile("/etc/group")
	if err != nil {
		return nil, fmt.Errorf("reading /etc/group: %w", err)
	}
	var out []groupEntry
	for _, line := range lines(data) {
		if g, ok := parseGroup(line); ok {
			out = append(out, g)
		}
	}
	return out, nil
}

// parsePasswd parses "name:pw:uid:gid:gecos:home:shell".
func parsePasswd(line string) (userEntry, bool) {
	f := strings.Split(line, ":")
	if len(f) < 4 || f[0] == "" {
		return userEntry{}, false
	}
	uid, err1 := strconv.ParseUint(f[2], 10, 32)
	gid, err2 := strconv.ParseUint(f[3], 10, 32)
	if err1 != nil || err2 != nil {
		return userEntry{}, false
	}
	return userEntry{Name: f[0], UID: uint32(uid), GID: uint32(gid)}, true
}

// parseGroup parses "name:pw:gid:member,member".
func parseGroup(line string) (groupEntry, bool) {
	f := strings.Split(line, ":")
	if len(f) < 3 || f[0] == "" {
		return groupEntry{}, false
	}
	gid, err := strconv.ParseUint(f[2], 10, 32)
	if err != nil {
		return groupEntry{}, false
	}
	g := groupEntry{Name: f[0], GID: uint32(gid)}
	if len(f) > 3 && f[3] != "" {
		g.Members = strings.Split(f[3], ",")
	}
	return g, true
}

func lines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func firstLine(data []byte) string {
	line, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(line)
}

func dedupe(ids []uint32) []uint32 {
	seen := map[uint32]bool{}
	out := ids[:0:0]
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
