package cli

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Options
	}{
		{
			name: "minimal",
			args: []string{"read", "/etc/shadow"},
			want: Options{Action: core.Read, Path: "/etc/shadow", Color: "auto"},
		},
		{
			name: "flags after positionals and aliases",
			args: []string{"rm", "/tmp/x", "-u", "www-data", "-g", "deploy", "-g", "33", "-a", "--color=never"},
			want: Options{
				Action: core.Delete, Path: "/tmp/x", User: "www-data",
				Groups: []string{"deploy", "33"}, All: true, Color: "never",
			},
		},
		{
			name: "pid and json",
			args: []string{"--pid", "1234", "--json", "-v", "x", "/usr/bin/foo"},
			want: Options{Action: core.Exec, Path: "/usr/bin/foo", PID: 1234, JSON: true, Verbose: true, Color: "auto"},
		},
		{
			name: "leading dash path after --",
			args: []string{"-q", "write", "--", "-rf"},
			want: Options{Action: core.Write, Path: "-rf", Quiet: true, Color: "auto"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse = %+v\nwant    %+v", got, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := map[string][]string{
		"no args":         {},
		"one arg":         {"read"},
		"three args":      {"read", "/a", "/b"},
		"bad action":      {"chmod", "/a"},
		"empty path":      {"read", ""},
		"bad color":       {"--color=sometimes", "read", "/a"},
		"pid with user":   {"-p", "1", "-u", "root", "read", "/a"},
		"zero pid":        {"-p", "0", "read", "/a"},
		"json with quiet": {"--json", "-q", "read", "/a"},
		"unknown flag":    {"--frobnicate", "read", "/a"},
	}
	for name, args := range tests {
		if _, err := Parse(args); err == nil || errors.Is(err, errHelp) {
			t.Errorf("%s: Parse(%q) err = %v, want usage error", name, args, err)
		}
	}
}

func TestMainExitCodes(t *testing.T) {
	tests := []struct {
		args      []string
		code      int
		stdoutHas string
		stderrHas string
	}{
		{[]string{"--help"}, ExitAllowed, "Usage:", ""},
		{[]string{"-h"}, ExitAllowed, "append", ""},
		{[]string{"--version"}, ExitAllowed, "whycant dev", ""},
		{[]string{"read"}, ExitUsage, "", "expected <action> <path>"},
		{[]string{"read", "/etc/hosts"}, ExitAllowed, "path:    /etc/hosts", ""},
	}
	for _, tt := range tests {
		var stdout, stderr bytes.Buffer
		code := Main(tt.args, &stdout, &stderr, sys.NewFake())
		if code != tt.code {
			t.Errorf("Main(%q) = %d, want %d", tt.args, code, tt.code)
		}
		if !strings.Contains(stdout.String(), tt.stdoutHas) {
			t.Errorf("Main(%q) stdout = %q, want it to contain %q", tt.args, stdout.String(), tt.stdoutHas)
		}
		if !strings.Contains(stderr.String(), tt.stderrHas) {
			t.Errorf("Main(%q) stderr = %q, want it to contain %q", tt.args, stderr.String(), tt.stderrHas)
		}
	}
}
