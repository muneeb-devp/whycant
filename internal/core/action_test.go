package core

import "testing"

func TestParseAction(t *testing.T) {
	tests := map[string]Action{
		"read": Read, "r": Read, "READ": Read,
		"write": Write, "w": Write,
		"append": Append,
		"exec":   Exec, "x": Exec, "run": Exec,
		"list": List, "ls": List,
		"traverse": Traverse, "cd": Traverse,
		"create": Create, "mk": Create, "touch": Create,
		"delete": Delete, "rm": Delete,
	}
	for in, want := range tests {
		got, err := ParseAction(in)
		if err != nil || got != want {
			t.Errorf("ParseAction(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "readx", "chmod", "a"} {
		if _, err := ParseAction(bad); err == nil {
			t.Errorf("ParseAction(%q) succeeded", bad)
		}
	}
}

func TestActionRoundTrip(t *testing.T) {
	for _, a := range Actions {
		got, err := ParseAction(a.String())
		if err != nil || got != a {
			t.Errorf("round trip %v: %v, %v", a, got, err)
		}
	}
	if got := Exec.Aliases(); len(got) != 2 || got[0] != "x" || got[1] != "run" {
		t.Errorf("Exec.Aliases() = %v", got)
	}
}

func TestPermString(t *testing.T) {
	tests := []struct {
		p           Perm
		full, short string
	}{
		{0, "---", ""},
		{PermR, "r--", "r"},
		{PermW | PermX, "-wx", "wx"},
		{PermR | PermW | PermX, "rwx", "rwx"},
	}
	for _, tt := range tests {
		if tt.p.String() != tt.full || tt.p.Short() != tt.short {
			t.Errorf("Perm(%d) = %q/%q, want %q/%q", tt.p, tt.p.String(), tt.p.Short(), tt.full, tt.short)
		}
	}
}
