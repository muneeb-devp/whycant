package binfmt

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseShebang(t *testing.T) {
	tests := []struct {
		in   string
		want Shebang
		ok   bool
	}{
		{"#!/bin/sh\necho", Shebang{Interpreter: "/bin/sh"}, true},
		{"#! /usr/bin/env  python3 \n", Shebang{Interpreter: "/usr/bin/env", Arg: "python3"}, true},
		{"#!/bin/bash\r\n", Shebang{Interpreter: "/bin/bash\r", CRLF: true}, true},
		{"#!/usr/bin/env bash\r\n", Shebang{Interpreter: "/usr/bin/env", Arg: "bash\r", CRLF: true}, true},
		{"#!/usr/bin/awk -f -x\n", Shebang{Interpreter: "/usr/bin/awk", Arg: "-f -x"}, true},
		{"#!/bin/sh\t-e\n", Shebang{Interpreter: "/bin/sh", Arg: "-e"}, true},
		{"#!\n", Shebang{}, true},
		{"#!/bin/sh", Shebang{Interpreter: "/bin/sh"}, true},
		{"echo hi\n", Shebang{}, false},
		{"", Shebang{}, false},
	}
	for _, tt := range tests {
		got, ok := ParseShebang([]byte(tt.in))
		if ok != tt.ok || got != tt.want {
			t.Errorf("ParseShebang(%q) = %+v, %v; want %+v, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func FuzzParseShebang(f *testing.F) {
	f.Add([]byte("#!/bin/sh\n"))
	f.Add([]byte("#!/usr/bin/env bash\r\n"))
	f.Add([]byte("#! \t /x\t\ty  \n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		sb, ok := ParseShebang(b)
		if !ok {
			return
		}
		for _, c := range sb.Interpreter {
			if c == ' ' || c == '\t' || c == '\n' {
				t.Fatalf("interpreter %q contains a separator", sb.Interpreter)
			}
		}
	})
}

func minimalELF(class int, machine elf.Machine, bo binary.ByteOrder, interp string) []byte {
	return MinimalELFOrder(class, machine, interp, bo)
}

func TestParseELF(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		class   int
		machine elf.Machine
		interp  string
	}{
		{"x86_64 dynamic", MinimalELF(64, elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2"), 64, elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2"},
		{"aarch64 static", MinimalELF(64, elf.EM_AARCH64, ""), 64, elf.EM_AARCH64, ""},
		{"arm 32-bit", MinimalELF(32, elf.EM_ARM, "/lib/ld-linux-armhf.so.3"), 32, elf.EM_ARM, "/lib/ld-linux-armhf.so.3"},
		{"big-endian", minimalELF(64, elf.EM_S390, binary.BigEndian, "/lib/ld64.so.1"), 64, elf.EM_S390, "/lib/ld64.so.1"},
	}
	for _, tt := range tests {
		e, err := ParseELF(tt.b)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if e.Class != tt.class || e.Machine != tt.machine || e.Interp != tt.interp {
			t.Errorf("%s: got %+v", tt.name, e)
		}
	}

	if _, err := ParseELF([]byte("#!/bin/sh")); !errors.Is(err, ErrNotELF) {
		t.Errorf("non-ELF: %v", err)
	}
	full := MinimalELF(64, elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2")
	var more *NeedMoreError
	if _, err := ParseELF(full[:100]); !errors.As(err, &more) || more.Size <= 100 {
		t.Errorf("truncated: %v", err)
	}
}

func TestMachineNames(t *testing.T) {
	native, compat := HostMachine("amd64")
	if native != elf.EM_X86_64 || compat != elf.EM_386 {
		t.Error("amd64 mapping")
	}
	if MachineName(elf.EM_AARCH64, 64) != "aarch64" || QemuName(elf.EM_AARCH64, 64) != "qemu-aarch64" {
		t.Error("aarch64 names")
	}
}

func FuzzParseELF(f *testing.F) {
	f.Add(MinimalELF(64, elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2"))
	f.Add(MinimalELF(32, elf.EM_ARM, ""))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = ParseELF(b)
	})
}
