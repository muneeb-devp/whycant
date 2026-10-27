package checks

import (
	"strings"
)

// lsmState is what whycant could learn about the active Linux Security
// Modules. It is read once per run.
type lsmState struct {
	selinux  bool
	apparmor bool
	// enforce is the SELinux mode: 1 enforcing, 0 permissive, -1 unknown.
	enforce int
}

// lsm detects the active LSMs from /sys/kernel/security/lsm, falling back to
// the per-module files when securityfs is not readable.
func (c *Context) lsm() *lsmState {
	if c.lsmCache != nil {
		return c.lsmCache
	}
	st := &lsmState{enforce: -1}
	c.lsmCache = st
	if c.Sys == nil {
		return st
	}
	if b, err := c.Sys.ReadFile("/sys/kernel/security/lsm"); err == nil {
		for _, name := range strings.Split(strings.TrimSpace(string(b)), ",") {
			switch name {
			case "selinux":
				st.selinux = true
			case "apparmor":
				st.apparmor = true
			}
		}
	} else {
		if _, err := c.Sys.Lstat("/sys/fs/selinux/enforce"); err == nil {
			st.selinux = true
		}
		if b, err := c.Sys.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil && strings.TrimSpace(string(b)) == "Y" {
			st.apparmor = true
		}
	}
	if st.selinux {
		if b, err := c.Sys.ReadFile("/sys/fs/selinux/enforce"); err == nil {
			switch strings.TrimSpace(string(b)) {
			case "1":
				st.enforce = 1
			case "0":
				st.enforce = 0
			}
		} else if out, err := c.Sys.Run("getenforce"); err == nil {
			switch strings.TrimSpace(string(out)) {
			case "Enforcing":
				st.enforce = 1
			case "Permissive":
				st.enforce = 0
			}
		}
	}
	return st
}

// logLines returns recent lines from the first readable source among
// candidates: a file path, or a command (name and args).
func (c *Context) logLines(sources ...[]string) (lines []string, source string, ok bool) {
	for _, src := range sources {
		var data []byte
		var err error
		if strings.HasPrefix(src[0], "/") && len(src) == 1 {
			data, err = c.Sys.ReadFile(src[0])
		} else {
			data, err = c.Sys.Run(src[0], src[1:]...)
		}
		if err != nil || len(data) == 0 {
			continue
		}
		return strings.Split(string(data), "\n"), strings.Join(src, " "), true
	}
	return nil, "", false
}

// trimLine shortens a log line for display.
func trimLine(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// lastN keeps the last n items.
func lastN(lines []string, n int) []string {
	if len(lines) > n {
		return lines[len(lines)-n:]
	}
	return lines
}
