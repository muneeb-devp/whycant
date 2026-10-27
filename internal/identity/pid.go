package identity

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
)

// FromPID builds the subject from a running process: its filesystem uid and
// gid (what the kernel uses for file access), supplementary groups,
// effective capabilities and security label.
func (r *Resolver) FromPID(pid int) (*core.Subject, error) {
	dir := "/proc/" + strconv.Itoa(pid)
	b, err := r.sys.ReadFile(dir + "/status")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no process with pid %d", pid)
		}
		return nil, fmt.Errorf("reading %s/status: %w", dir, err)
	}
	st := parseStatus(string(b))

	uids, gids := st["Uid"], st["Gid"]
	if len(uids) < 4 || len(gids) < 4 {
		return nil, fmt.Errorf("unexpected format in %s/status", dir)
	}
	s := &core.Subject{Source: "pid:" + strconv.Itoa(pid)}
	s.UID, err = parseID(uids[3]) // fsuid
	if err != nil {
		return nil, err
	}
	if s.GID, err = parseID(gids[3]); err != nil { // fsgid
		return nil, err
	}
	s.Groups = []uint32{s.GID}
	for _, g := range st["Groups"] {
		gid, err := parseID(g)
		if err != nil {
			return nil, err
		}
		s.Groups = append(s.Groups, gid)
	}
	s.Groups = dedupe(s.Groups)
	if capEff := st["CapEff"]; len(capEff) == 1 {
		caps, err := strconv.ParseUint(capEff[0], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("bad CapEff %q", capEff[0])
		}
		s.Caps = core.CapSet(caps)
	}
	if name := st["Name"]; len(name) > 0 {
		s.Process = strings.Join(name, " ")
	}
	s.PID = pid
	if label, err := r.sys.ReadFile(dir + "/attr/current"); err == nil {
		s.Label = strings.TrimRight(strings.TrimSpace(string(label)), "\x00")
	}
	if u, _, err := r.lookupUser(strconv.FormatUint(uint64(s.UID), 10)); err == nil {
		s.Name = u.Name
		if configured, err := r.groupsOf(u); err == nil {
			s.StaleGroups = Stale(configured, s.Groups)
		}
	}
	return s, nil
}

// parseStatus splits /proc/<pid>/status into key -> fields.
func parseStatus(text string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			out[k] = strings.Fields(v)
		}
	}
	return out
}

func parseID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("bad id %q", s)
	}
	return uint32(n), nil
}
