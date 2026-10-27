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

func TestTruncateMiddle(t *testing.T) {
	tests := []struct {
		in   string
		w    int
		want string
	}{
		{"/short", 20, "/short"},
		{"/very/deep/nested/long/path", 18, "/very/…/long/path"},
		{"/srv/projects/customer-portal", 17, "…/customer-portal"},
		{"/a/averyveryverylongcomponent", 12, "…ngcomponent"},
	}
	for _, tt := range tests {
		got := truncateMiddle(tt.in, tt.w)
		if got != tt.want || width(got) > max(tt.w, width(tt.in)) {
			t.Errorf("truncateMiddle(%q, %d) = %q, want %q", tt.in, tt.w, got, tt.want)
		}
	}
}

func TestWrap(t *testing.T) {
	h := renderer{Options: Options{Width: 20}}
	got := h.indent("one two three four five six seven", "  ")
	want := "  one two three four\n  five six seven\n"
	if got != want {
		t.Errorf("indent = %q, want %q", got, want)
	}
}
