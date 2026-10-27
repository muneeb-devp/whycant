package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/muneeb-devp/whycant/internal/sys"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/")

const goldenDir = "../../testdata"

const worldPasswd = `root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/bash
`

const worldGroup = `root:x:0:
shadow:x:42:
www-data:x:33:
alice:x:1000:
deploy:x:1001:alice
`

// world is a small system where whycant runs as alice (uid 1000, in group
// deploy) and getent/id are unavailable, so /etc files are used.
func world() *sys.Fake {
	f := sys.NewFake()
	f.UID, f.GID, f.Groups = 1000, 1000, []uint32{1000, 1001}
	f.File("/etc/passwd", 0o644, 0, 0, worldPasswd)
	f.File("/etc/group", 0o644, 0, 0, worldGroup)
	f.File("/etc/shadow", 0o640, 0, 42, "")
	f.Dir("/home/alice", 0o755, 1000, 1000)
	f.Dir("/srv", 0o755, 0, 0)
	return f
}

func TestScenarios(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *sys.Fake)
		args  []string
		code  int
	}{
		{
			// Scenario 1, and the README example.
			name: "readme_example",
			setup: func(f *sys.Fake) {
				f.Dir("/srv/app", 0o750, 1001, 1001)
				f.Dir("/srv/app/config", 0o750, 1001, 1001)
				f.File("/srv/app/config/db.yml", 0o640, 1001, 1001, "")
			},
			args: []string{"-u", "www-data", "read", "/srv/app/config/db.yml"},
			code: ExitDenied,
		},
		{
			name: "quiet",
			setup: func(f *sys.Fake) {
				f.Dir("/srv/app", 0o750, 1001, 1001)
			},
			args: []string{"-q", "-u", "www-data", "list", "/srv/app"},
			code: ExitDenied,
		},
		{
			// Scenario 2.
			name: "owner_precedence",
			setup: func(f *sys.Fake) {
				f.File("/home/alice/notes.txt", 0o047, 1000, 1000, "")
			},
			args: []string{"-u", "alice", "read", "/home/alice/notes.txt"},
			code: ExitDenied,
		},
		{
			// Scenario 3.
			name: "group_grants",
			setup: func(f *sys.Fake) {
				f.Dir("/srv/shared", 0o750, 0, 1001)
				f.File("/srv/shared/report.txt", 0o640, 0, 1001, "")
			},
			args: []string{"-v", "-u", "alice", "read", "/srv/shared/report.txt"},
			code: ExitAllowed,
		},
		{
			name: "group_lacks_bit",
			setup: func(f *sys.Fake) {
				f.File("/srv/shared.log", 0o646, 0, 1001, "")
			},
			args: []string{"-u", "alice", "write", "/srv/shared.log"},
			code: ExitDenied,
		},
		{
			// Scenario 19, DAC part.
			name: "root_reads_000",
			setup: func(f *sys.Fake) {
				f.File("/home/alice/private", 0o000, 1000, 1000, "")
			},
			args: []string{"-u", "root", "read", "/home/alice/private"},
			code: ExitAllowed,
		},
		{
			// Scenario 19, DAC part.
			name: "root_exec_without_x",
			setup: func(f *sys.Fake) {
				f.File("/home/alice/tool.sh", 0o644, 1000, 1000, "#!/bin/sh\n")
			},
			args: []string{"-u", "root", "exec", "/home/alice/tool.sh"},
			code: ExitDenied,
		},
		{
			// Scenario 20.
			name: "cannot_inspect",
			setup: func(f *sys.Fake) {
				f.Dir("/root", 0o700, 0, 0)
				f.Dir("/root/.ssh", 0o700, 0, 0).Err = syscall.EACCES
			},
			args: []string{"-u", "root", "read", "/root/.ssh/id_ed25519"},
			code: ExitIndeterminate,
		},
		{
			name:  "missing",
			setup: func(*sys.Fake) {},
			args:  []string{"-u", "www-data", "read", "/srv/nope/config.yml"},
			code:  ExitDenied,
		},
		{
			name: "all_blockers",
			setup: func(f *sys.Fake) {
				f.Dir("/srv/app", 0o750, 1001, 1001)
				f.File("/srv/app/secret.txt", 0o600, 1001, 1001, "")
			},
			args: []string{"--all", "-u", "www-data", "read", "/srv/app/secret.txt"},
			code: ExitDenied,
		},
		{
			name:  "current_user",
			setup: func(*sys.Fake) {},
			args:  []string{"read", "/etc/shadow"},
			code:  ExitDenied,
		},
		{
			// Fix commands must stay safe for hostile names (scenario 22).
			name: "nasty_path",
			setup: func(f *sys.Fake) {
				f.File("/srv/it's a -file; rm -rf ~", 0o600, 1001, 1001, "")
			},
			args: []string{"-u", "www-data", "read", "--", "/srv/it's a -file; rm -rf ~"},
			code: ExitDenied,
		},
		{
			name: "list_without_x",
			setup: func(f *sys.Fake) {
				f.Dir("/srv/drop", 0o754, 1001, 1001)
			},
			args: []string{"-u", "www-data", "list", "/srv/drop"},
			code: ExitAllowed,
		},
		{
			name: "exec_directory",
			setup: func(f *sys.Fake) {
				f.Dir("/srv/bin", 0o755, 0, 0)
			},
			args: []string{"exec", "/srv/bin"},
			code: ExitDenied,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := world()
			tt.setup(f)
			var stdout, stderr bytes.Buffer
			code := Main(tt.args, &stdout, &stderr, f)
			if stderr.Len() > 0 {
				t.Errorf("stderr: %s", stderr.String())
			}
			if code != tt.code {
				t.Errorf("exit code = %d, want %d", code, tt.code)
			}
			golden(t, tt.name, "$ whycant "+shellArgs(tt.args)+"\n\n"+stdout.String())
		})
	}
}

// TestREADMEExample keeps the README in sync with real output.
func TestREADMEExample(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(goldenDir, "readme_example.golden"))
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(readme, want) {
		t.Errorf("README.md does not contain the output in testdata/readme_example.golden:\n%s", want)
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join(goldenDir, name+".golden")
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/cli -update)", err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s\n--- got ---\n%s--- want ---\n%s", p, got, want)
	}
}

func shellArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " '\";~") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}
