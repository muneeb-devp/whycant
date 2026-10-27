package cli

import (
	"os"
	"testing"

	"github.com/muneeb-devp/whycant/internal/sys"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestLSMScenarios covers SELinux and AppArmor with recorded log fixtures.
func TestLSMScenarios(t *testing.T) {
	audit := fixture(t, "audit.log")
	kern := fixture(t, "kern-apparmor.log")

	selinux := func(f *sys.Fake, enforce string) {
		f.File("/sys/kernel/security/lsm", 0o444, 0, 0, "lockdown,capability,yama,selinux,bpf\n")
		f.File("/sys/fs/selinux/enforce", 0o444, 0, 0, enforce)
		f.File("/etc/passwd", 0o644, 0, 0, worldPasswd+"apache:x:48:48::/usr/share/httpd:/sbin/nologin\n")
		f.Dir("/srv/www", 0o755, 0, 0)
		page := f.File("/srv/www/index.html", 0o644, 0, 0, "hi\n")
		page.Ino = 4242
		page.Xattrs = map[string][]byte{"security.selinux": []byte("unconfined_u:object_r:user_home_t:s0\x00")}
		f.SetCommand("system_u:object_r:httpd_sys_content_t:s0\n", nil, "matchpathcon", "-n", "/srv/www/index.html")
	}

	tests := []struct {
		name  string
		setup func(f *sys.Fake)
		args  []string
		code  int
	}{
		{
			name: "selinux_denied",
			setup: func(f *sys.Fake) {
				selinux(f, "1\n")
				f.File("/var/log/audit/audit.log", 0o600, 0, 0, audit)
			},
			args: []string{"-u", "apache", "read", "/srv/www/index.html"},
			code: ExitDenied,
		},
		{
			name: "selinux_permissive",
			setup: func(f *sys.Fake) {
				selinux(f, "0\n")
				f.File("/var/log/audit/audit.log", 0o600, 0, 0, audit)
			},
			args: []string{"-u", "apache", "read", "/srv/www/index.html"},
			code: ExitAllowed,
		},
		{
			name: "selinux_no_log_access",
			setup: func(f *sys.Fake) {
				selinux(f, "1\n")
			},
			args: []string{"-u", "apache", "read", "/srv/www/index.html"},
			code: ExitAllowed,
		},
		{
			name: "apparmor_denied",
			setup: func(f *sys.Fake) {
				f.File("/sys/kernel/security/lsm", 0o444, 0, 0, "lockdown,capability,landlock,yama,apparmor\n")
				f.File("/srv/mysql/my.cnf", 0o644, 0, 0, "")
				f.SetCommand(kern, nil, "journalctl", "-k", "--since=-24h", "-o", "cat", "--no-pager")
			},
			args: []string{"-u", "www-data", "read", "/srv/mysql/my.cnf"},
			code: ExitDenied,
		},
		{
			name: "apparmor_clean",
			setup: func(f *sys.Fake) {
				f.File("/sys/kernel/security/lsm", 0o444, 0, 0, "lockdown,capability,apparmor\n")
				f.File("/srv/mysql/other.txt", 0o644, 0, 0, "")
				f.SetCommand(kern, nil, "journalctl", "-k", "--since=-24h", "-o", "cat", "--no-pager")
			},
			args: []string{"-u", "www-data", "read", "/srv/mysql/other.txt"},
			code: ExitAllowed,
		},
		{
			name: "container",
			setup: func(f *sys.Fake) {
				f.File("/.dockerenv", 0o644, 0, 0, "")
				f.File("/proc/self/uid_map", 0o444, 0, 0, "         0     100000      65536\n")
				f.File("/srv/x", 0o644, 0, 0, "")
			},
			args: []string{"read", "/srv/x"},
			code: ExitAllowed,
		},
	}
	for _, tt := range tests {
		runScenario(t, tt.name, tt.setup, tt.args, tt.code)
	}
}
