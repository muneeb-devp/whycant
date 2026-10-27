package report

import "testing"

func TestSanitize(t *testing.T) {
	tests := map[string]string{
		"plain\nlines":     "plain\nlines",
		"/tmp/\x1b[2Jboom": `/tmp/\x1b[2Jboom`,
		"cr\rhere\ttab":    `cr\x0dhere\x09tab`,
		"ünïcode ✓":        "ünïcode ✓",
	}
	for in, want := range tests {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
