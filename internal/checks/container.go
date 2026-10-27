package checks

import (
	"fmt"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
)

// Container notes when whycant runs inside a container or a non-initial
// user namespace, where it only sees the inside view. Detection only.
type Container struct{}

// Name implements Check.
func (Container) Name() string { return "container" }

// Applies implements Check: once per run, on "/".
func (Container) Applies(ctx *Context, n *core.Node) bool {
	return n.Path == "/" && n.Exists && ctx.Sys != nil
}

// Evaluate implements Check.
func (Container) Evaluate(ctx *Context, _ *core.Node) []core.Finding {
	var out []core.Finding
	if kind := containerKind(ctx); kind != "" {
		out = append(out, core.Finding{
			Check: "container", NodePath: "/", Severity: core.Info, Confidence: core.Likely,
			Summary: "running inside a container (" + kind + ")",
			Detail:  "Results reflect the view from inside this container: its users, mounts and\nfiles, which can differ from the host's.",
		})
	}
	if m, ok := userNamespace(ctx); ok {
		out = append(out, core.Finding{
			Check: "container", NodePath: "/", Severity: core.Info, Confidence: core.Certain,
			Summary: "running in a user namespace",
			Detail:  fmt.Sprintf("uids are mapped (%s), so owners and root here are not the host's.\nFiles owned by unmapped ids show up as nobody.", m),
		})
	}
	return out
}

func containerKind(ctx *Context) string {
	if _, err := ctx.Sys.Lstat("/.dockerenv"); err == nil {
		return "docker"
	}
	if _, err := ctx.Sys.Lstat("/run/.containerenv"); err == nil {
		return "podman"
	}
	if b, err := ctx.Sys.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, kind := range []string{"kubepods", "docker", "containerd", "lxc", "libpod"} {
			if strings.Contains(s, kind) {
				return kind
			}
		}
	}
	if b, err := ctx.Sys.ReadFile("/proc/1/environ"); err == nil {
		for _, kv := range strings.Split(string(b), "\x00") {
			if v, ok := strings.CutPrefix(kv, "container="); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// userNamespace reports a uid_map other than the initial namespace's
// identity map "0 0 4294967295".
func userNamespace(ctx *Context) (string, bool) {
	b, err := ctx.Sys.ReadFile("/proc/self/uid_map")
	if err != nil {
		return "", false
	}
	m := strings.Join(strings.Fields(string(b)), " ")
	if m == "" || m == "0 0 4294967295" {
		return "", false
	}
	return m, true
}
