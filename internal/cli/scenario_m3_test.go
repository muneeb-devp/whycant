package cli

import (
	"debug/elf"
	"testing"

	"github.com/muneeb-devp/whycant/internal/binfmt"
	"github.com/muneeb-devp/whycant/internal/sys"
)

// withSystem installs a minimal x86_64 userland: a loader, sh and env.
func withSystem(f *sys.Fake) {
	f.File("/lib64/ld-linux-x86-64.so.2", 0o755, 0, 0, string(binfmt.MinimalELF(64, elf.EM_X86_64, "")))
	dyn := string(binfmt.MinimalELF(64, elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2"))
	f.File("/usr/bin/bash", 0o755, 0, 0, dyn)
	f.File("/usr/bin/env", 0o755, 0, 0, dyn)
	f.Symlink("/bin", "usr/bin", 0, 0)
}

// TestExecScenarios covers the brief's milestone 3 scenarios.
func TestExecScenarios(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *sys.Fake)
		args  []string
		code  int
	}{
		{
			// Scenario 12.
			name: "script_not_readable",
			setup: func(f *sys.Fake) {
				withSystem(f)
				f.File("/srv/deploy.sh", 0o711, 1001, 1001, "#!/bin/bash\necho deploy\n")
			},
			args: []string{"-u", "www-data", "exec", "/srv/deploy.sh"},
			code: ExitDenied,
		},
		{
			// Scenario 13.
			name: "script_crlf",
			setup: func(f *sys.Fake) {
				withSystem(f)
				f.File("/srv/build.sh", 0o755, 1000, 1000, "#!/bin/bash\r\necho hi\r\n")
			},
			args: []string{"-u", "alice", "exec", "/srv/build.sh"},
			code: ExitDenied,
		},
		{
			// Scenario 14.
			name: "script_missing_interpreter",
			setup: func(f *sys.Fake) {
				withSystem(f)
				f.File("/srv/tool.py", 0o755, 1000, 1000, "#!/usr/local/bin/python3.12\nprint(1)\n")
			},
			args: []string{"-u", "alice", "exec", "/srv/tool.py"},
			code: ExitDenied,
		},
		{
			name: "script_env_interpreter",
			setup: func(f *sys.Fake) {
				withSystem(f)
				f.File("/srv/run.sh", 0o755, 1000, 1000, "#!/usr/bin/env bash\necho hi\n")
			},
			args: []string{"-u", "alice", "exec", "/srv/run.sh"},
			code: ExitAllowed,
		},
		{
			name: "script_env_not_on_path",
			setup: func(f *sys.Fake) {
				withSystem(f)
				f.File("/srv/run.js", 0o755, 1000, 1000, "#!/usr/bin/env node\nconsole.log(1)\n")
			},
			args: []string{"-u", "alice", "exec", "/srv/run.js"},
			code: ExitDenied,
		},
		{
			name: "interpreter_not_executable",
			setup: func(f *sys.Fake) {
				withSystem(f)
				f.File("/opt/py/bin/python3", 0o750, 0, 0, string(binfmt.MinimalELF(64, elf.EM_X86_64, "")))
				f.File("/srv/job.py", 0o755, 33, 33, "#!/opt/py/bin/python3\n")
			},
			args: []string{"-u", "www-data", "exec", "/srv/job.py"},
			code: ExitDenied,
		},
		{
			// Scenario 15.
			name: "elf_wrong_arch",
			setup: func(f *sys.Fake) {
				withSystem(f)
				f.File("/srv/app-arm64", 0o755, 0, 0, string(binfmt.MinimalELF(64, elf.EM_AARCH64, "/lib/ld-linux-aarch64.so.1")))
			},
			args: []string{"exec", "/srv/app-arm64"},
			code: ExitDenied,
		},
		{
			name: "elf_wrong_arch_qemu",
			setup: func(f *sys.Fake) {
				withSystem(f)
				f.File("/srv/app-arm64", 0o755, 0, 0, string(binfmt.MinimalELF(64, elf.EM_AARCH64, "")))
				f.File("/proc/sys/fs/binfmt_misc/qemu-aarch64", 0o644, 0, 0, "enabled\n")
			},
			args: []string{"exec", "/srv/app-arm64"},
			code: ExitAllowed,
		},
		{
			// Scenario 16.
			name: "elf_missing_loader",
			setup: func(f *sys.Fake) {
				withSystem(f)
				f.File("/srv/glibc-app", 0o755, 0, 0, string(binfmt.MinimalELF(64, elf.EM_X86_64, "/lib/ld-musl-x86_64.so.1")))
			},
			args: []string{"exec", "/srv/glibc-app"},
			code: ExitDenied,
		},
		{
			name: "unknown_format",
			setup: func(f *sys.Fake) {
				f.File("/srv/notes.txt", 0o755, 1000, 1000, "just text\n")
			},
			args: []string{"exec", "/srv/notes.txt"},
			code: ExitDenied,
		},
		{
			name: "disk_full",
			setup: func(f *sys.Fake) {
				f.File("/srv/data.db", 0o666, 0, 0, "")
				f.FS["/"] = sys.FSStats{Bsize: 4096, Blocks: 1000, Bfree: 10, Bavail: 0, Files: 100, Ffree: 50}
			},
			args: []string{"-u", "alice", "write", "/srv/data.db"},
			code: ExitAllowed,
		},
	}
	for _, tt := range tests {
		runScenario(t, tt.name, tt.setup, tt.args, tt.code)
	}
}
