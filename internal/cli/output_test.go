package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/muneeb-devp/whycant/internal/acl"
	"github.com/muneeb-devp/whycant/internal/sys"
)

func readmeWorld(f *sys.Fake) {
	f.Dir("/srv/app", 0o750, 1001, 1001)
	f.Dir("/srv/app/config", 0o750, 1001, 1001)
	f.File("/srv/app/config/db.yml", 0o640, 1001, 1001, "")
}

// TestJSONOutput pins the JSON schema with golden files.
func TestJSONOutput(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *sys.Fake)
		args  []string
		code  int
	}{
		{"json_denied", readmeWorld, []string{"--json", "-u", "www-data", "read", "/srv/app/config/db.yml"}, ExitDenied},
		{"json_allowed_with_warning", func(f *sys.Fake) {
			withACL(f.Dir("/srv/drop", 0o754, 1001, 1001), acl.XattrAccess,
				acl.Entry{Tag: acl.TagUserObj, Perm: 7}, acl.Entry{Tag: acl.TagUser, Perm: 4, ID: 1000},
				acl.Entry{Tag: acl.TagGroupObj, Perm: 5}, acl.Entry{Tag: acl.TagMask, Perm: 5}, acl.Entry{Tag: acl.TagOther, Perm: 4})
			f.Files["/srv/drop"].Flags = sys.FlagAppendOnly
		}, []string{"--json", "-u", "alice", "list", "/srv/drop"}, ExitAllowed},
		{"json_unknown", func(f *sys.Fake) {
			f.Dir("/root", 0o700, 0, 0)
			f.Dir("/root/.ssh", 0o700, 0, 0).Err = errEACCES
		}, []string{"--json", "-u", "root", "read", "/root/.ssh/id_ed25519"}, ExitIndeterminate},
	}
	for _, tt := range tests {
		runScenario(t, tt.name, tt.setup, tt.args, tt.code)
	}
}

func TestJSONIsValid(t *testing.T) {
	f := world()
	readmeWorld(f)
	var stdout, stderr bytes.Buffer
	Main([]string{"--json", "-u", "www-data", "read", "/srv/app/config/db.yml"}, &stdout, &stderr, f)
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	for _, key := range []string{"schema_version", "verdict", "confidence", "action", "path", "subject", "chain", "findings", "warnings", "verify"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
}

func TestTerminalOutput(t *testing.T) {
	run := func(setup func(f *sys.Fake), args ...string) string {
		f := world()
		readmeWorld(f)
		setup(f)
		var stdout, stderr bytes.Buffer
		Main(args, &stdout, &stderr, f)
		return stdout.String()
	}
	args := []string{"-u", "www-data", "read", "/srv/app/config/db.yml"}

	out := run(func(f *sys.Fake) { f.TTY, f.Width = true, 200 }, args...)
	if !strings.Contains(out, "\x1b[31m✗\x1b[0m") || !strings.Contains(out, "\x1b[1mWhy\x1b[0m") {
		t.Errorf("no color on a TTY:\n%q", out)
	}
	out = run(func(f *sys.Fake) { f.TTY, f.Env = true, map[string]string{"NO_COLOR": "1"} }, args...)
	if strings.Contains(out, "\x1b[") {
		t.Error("NO_COLOR ignored")
	}
	out = run(func(*sys.Fake) {}, append([]string{"--color=always"}, args...)...)
	if !strings.Contains(out, "\x1b[") {
		t.Error("--color=always ignored")
	}
	out = run(func(*sys.Fake) {}, args...)
	if strings.Contains(out, "\x1b[") {
		t.Error("color when not a TTY")
	}

	out = run(func(f *sys.Fake) { f.Env = map[string]string{"LANG": "C"} }, args...)
	if strings.ContainsAny(out, "✓✗←·") || !strings.Contains(out, "NO traverse   <- blocked here") {
		t.Errorf("ASCII fallback:\n%s", out)
	}
	out = run(func(f *sys.Fake) { f.Env = map[string]string{"LANG": "en_US.UTF-8"} }, args...)
	if !strings.Contains(out, "✗ traverse") {
		t.Error("UTF-8 locale fell back to ASCII")
	}
}

func TestNarrowTerminal(t *testing.T) {
	runScenario(t, "narrow_terminal", func(f *sys.Fake) {
		f.TTY, f.Width = true, 60
		f.Env = map[string]string{"NO_COLOR": "1"}
		f.Dir("/srv/projects/customer-portal/releases/2026-10-28", 0o750, 1001, 1001)
		f.File("/srv/projects/customer-portal/releases/2026-10-28/config/database.yml", 0o640, 1001, 1001, "")
	}, []string{"-u", "www-data", "read", "/srv/projects/customer-portal/releases/2026-10-28/config/database.yml"}, ExitDenied)
}

var errEACCES = syscallEACCES()
