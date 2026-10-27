package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/muneeb-devp/whycant/internal/sys"
)

// probeAs makes the fake answer probes with a fixed exit code, recording
// the credentials and arguments it was called with.
func probeAs(f *sys.Fake, code int, got *[]string) {
	f.ProbeFunc = func(cred sys.Credential, args ...string) (int, string, error) {
		*got = append([]string{strings.Repeat("u", int(min(cred.UID, 1)))}, args...)
		return code, "", nil
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name      string
		probeCode int
		args      []string
		code      int
		wantArgs  string
		has       string
	}{
		{
			"agrees denied", 1,
			[]string{"--verify", "-u", "www-data", "read", "/srv/app/config/db.yml"},
			ExitDenied,
			"u __probe read /srv/app/config/db.yml", "the kernel agrees: access(2) as www-data says denied",
		},
		{
			"disagrees", 0,
			[]string{"--verify", "-u", "www-data", "read", "/srv/app/config/db.yml"},
			ExitVerifyMismatch,
			"", "This is a whycant bug",
		},
		{
			"probe error", 2,
			[]string{"--verify", "-u", "www-data", "read", "/srv/app/config/db.yml"},
			ExitDenied,
			"", "the probe failed",
		},
		// Sticky and script rules are invisible to access(2); the comparison
		// leaves them out instead of reporting a false mismatch.
		{
			"sticky not compared", 0,
			[]string{"--verify", "-u", "www-data", "delete", "/tmp/alice-file"},
			ExitDenied,
			"u __probe delete /tmp/alice-file", "the kernel agrees",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := world()
			readmeWorld(f)
			f.Dir("/tmp", 0o1777, 0, 0)
			f.File("/tmp/alice-file", 0o644, 1000, 1000, "")
			f.UID, f.GID, f.Groups = 0, 0, []uint32{0}
			var got []string
			probeAs(f, tt.probeCode, &got)
			var stdout, stderr bytes.Buffer
			code := Main(tt.args, &stdout, &stderr, f)
			if code != tt.code {
				t.Errorf("exit = %d, want %d\n%s%s", code, tt.code, stdout.String(), stderr.String())
			}
			if tt.wantArgs != "" && strings.Join(got, " ") != tt.wantArgs {
				t.Errorf("probe args = %q, want %q", strings.Join(got, " "), tt.wantArgs)
			}
			if !strings.Contains(stdout.String(), tt.has) {
				t.Errorf("output missing %q:\n%s", tt.has, stdout.String())
			}
		})
	}
}

func TestVerifyJSON(t *testing.T) {
	f := world()
	readmeWorld(f)
	f.UID = 0
	var got []string
	probeAs(f, 1, &got)
	var stdout, stderr bytes.Buffer
	Main([]string{"--json", "--verify", "-u", "www-data", "read", "/srv/app/config/db.yml"}, &stdout, &stderr, f)
	if !strings.Contains(stdout.String(), `"verify": {
    "probe": "denied",
    "match": true
  }`) {
		t.Errorf("JSON verify block:\n%s", stdout.String())
	}
}

func TestProbeSubcommand(t *testing.T) {
	f := world()
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"__probe", "read", "/etc/passwd"}, &stdout, &stderr, f); code != 0 {
		t.Errorf("probe existing = %d", code)
	}
	if code := Main([]string{"__probe", "read", "/nope"}, &stdout, &stderr, f); code != 1 {
		t.Errorf("probe missing = %d", code)
	}
	if code := Main([]string{"__probe", "read"}, &stdout, &stderr, f); code != 2 {
		t.Errorf("probe usage = %d", code)
	}
}

func TestPIDSubject(t *testing.T) {
	runScenario(t, "pid_subject", func(f *sys.Fake) {
		readmeWorld(f)
		f.File("/proc/812/status", 0o444, 0, 0,
			"Name:\tnginx\nUid:\t33\t33\t33\t33\nGid:\t33\t33\t33\t33\nGroups:\t33\nCapEff:\t0000000000000000\n")
		// www-data was added to deploy after nginx started.
		f.Files["/etc/group"].Content = []byte(strings.Replace(worldGroup, "deploy:x:1001:alice", "deploy:x:1001:alice,www-data", 1))
	}, []string{"--pid", "812", "read", "/srv/app/config/db.yml"}, ExitDenied)
}
