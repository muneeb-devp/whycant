//go:build integration

// Package integration runs whycant against a real kernel. The tests need
// root in a throwaway environment (make integration runs them in a
// privileged container): they create users, mount filesystems and set ACLs
// and file attributes.
package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var (
	binary string // the whycant binary under test
	work   string // a scratch filesystem that supports ACLs and chattr
)

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Println("integration tests need root; run them with: make integration")
		os.Exit(0)
	}
	code, err := setup()
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		os.Exit(1)
	}
	defer teardown()
	code = m.Run()
	teardown()
	os.Exit(code)
}

func setup() (int, error) {
	dir, err := os.MkdirTemp("", "whycant-it")
	if err != nil {
		return 0, err
	}
	// Subjects run the binary as the --verify probe, so they must reach it.
	if err := os.Chmod(dir, 0o755); err != nil {
		return 0, err
	}
	binary = filepath.Join(dir, "whycant")
	build := exec.Command("go", "build", "-o", binary, "./cmd/whycant")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("go build: %v\n%s", err, out)
	}

	// ext4 on a loop device behaves like a normal disk (ACLs, chattr);
	// fall back to tmpfs where loop devices are unavailable.
	work = "/work"
	script := `
mkdir -p /work
if ! mountpoint -q /work; then
  truncate -s 64M /tmp/whycant-work.img
  mkfs.ext4 -q -F /tmp/whycant-work.img
  mount -o loop /tmp/whycant-work.img /work 2>/dev/null || mount -t tmpfs -o size=64m tmpfs /work
fi
chmod 755 /work
getent group deploy >/dev/null || groupadd -g 1001 deploy
id alice  >/dev/null 2>&1 || useradd -M -u 1000 -U alice
id deploy >/dev/null 2>&1 || useradd -M -u 1001 -g deploy deploy
usermod -aG deploy alice
`
	if out, err := exec.Command("bash", "-euc", script).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("preparing /work: %v\n%s", err, out)
	}
	return 0, nil
}

func teardown() {
	_ = exec.Command("bash", "-c", "chattr -R -ia /work 2>/dev/null; umount -R /work 2>/dev/null").Run()
}

// scenario is one setup script and the whycant invocations to check
// against it. $W in scripts and arguments is the scenario's own directory.
type scenario struct {
	name    string
	setup   string
	cleanup string
	runs    []run
	// requires is a shell condition; the scenario is skipped when it fails.
	requires string
	// prepare runs after setup, for files easier to make in Go.
	prepare func(w string) error
}

type run struct {
	args []string
	code int
	// as runs whycant itself as another user (setpriv arguments).
	as []string
}

func TestScenarios(t *testing.T) {
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			w := filepath.Join(work, sc.name)
			if sc.requires != "" {
				if err := exec.Command("bash", "-c", sc.requires).Run(); err != nil {
					t.Skipf("requirement not met: %s", sc.requires)
				}
			}
			if err := os.MkdirAll(w, 0o755); err != nil {
				t.Fatal(err)
			}
			shell(t, w, sc.setup)
			if sc.prepare != nil {
				if err := sc.prepare(w); err != nil {
					t.Fatal(err)
				}
			}
			if sc.cleanup != "" {
				t.Cleanup(func() { shell(t, w, sc.cleanup) })
			}
			for _, r := range sc.runs {
				args := make([]string, len(r.args))
				for i, a := range r.args {
					args[i] = strings.ReplaceAll(a, "$W", w)
				}
				name, argv := binary, args
				if r.as == nil {
					// Every run is cross-checked against the kernel; a
					// disagreement exits 4 and fails the test.
					argv = append([]string{"--verify"}, args...)
				} else {
					name, argv = "setpriv", append(append(append([]string{}, r.as...), binary), args...)
				}
				if r.as == nil && !strings.Contains(strings.Join(argv, " "), "--verify") {
					t.Fatal("run is not verified")
				}
				cmd := exec.Command(name, argv...)
				cmd.Env = append(os.Environ(), "NO_COLOR=1")
				var out bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &out
				err := cmd.Run()
				code := 0
				if ee, ok := err.(*exec.ExitError); ok {
					code = ee.ExitCode()
				} else if err != nil {
					t.Fatalf("running whycant: %v", err)
				}
				if code != r.code {
					t.Errorf("whycant %s: exit %d, want %d\n%s", strings.Join(argv, " "), code, r.code, out.String())
				}
				if r.as == nil && !strings.Contains(out.String(), "the kernel agrees") {
					t.Errorf("whycant %s: not confirmed by the kernel\n%s", strings.Join(argv, " "), out.String())
				}
			}
		})
	}
}

func shell(t *testing.T, w, script string) {
	t.Helper()
	cmd := exec.Command("bash", "-euc", script)
	cmd.Env = append(os.Environ(), "W="+w)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s\n%s", err, script, out)
	}
}
