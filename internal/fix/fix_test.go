package fix

import (
	"testing"

	"github.com/muneeb-devp/whycant/internal/core"
)

func TestQuote(t *testing.T) {
	tests := map[string]string{
		"":                   "''",
		"/srv/app":           "/srv/app",
		"u:www-data:rx":      "u:www-data:rx",
		"/srv/my app":        "'/srv/my app'",
		"/srv/it's":          `'/srv/it'\''s'`,
		"/tmp/a\nb":          "'/tmp/a\nb'",
		"/tmp/$HOME":         "'/tmp/$HOME'",
		"/tmp/`id`":          "'/tmp/`id`'",
		"/tmp/*":             "'/tmp/*'",
		"/tmp/a;rm -rf /":    "'/tmp/a;rm -rf /'",
		"-rf":                "-rf",
		"/tmp/\\back":        "'/tmp/\\back'",
		"/tmp/'":             `'/tmp/'\'''`,
		"/tmp/ünïcode":       "'/tmp/ünïcode'",
		"/tmp/tab\there":     "'/tmp/tab\there'",
		"/tmp/!bang":         "'/tmp/!bang'",
		"/tmp/semi;colon&&x": "'/tmp/semi;colon&&x'",
	}
	for in, want := range tests {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCommand(t *testing.T) {
	got := Command(true, "setfacl", "-m", "u:www-data:x", "/srv/my app")
	if want := "sudo setfacl -m u:www-data:x '/srv/my app'"; got != want {
		t.Errorf("Command = %q, want %q", got, want)
	}
	if got := Command(false, "chmod", "u+r", "/a"); got != "chmod u+r /a" {
		t.Errorf("Command = %q", got)
	}
}

func TestRank(t *testing.T) {
	fixes := []core.Fix{
		{Description: "a", Risk: core.RiskHigh},
		{Description: "b", Risk: core.RiskLow},
		{Description: "c", Risk: core.RiskMedium},
		{Description: "d", Risk: core.RiskLow},
	}
	Rank(fixes)
	got := ""
	for _, f := range fixes {
		got += f.Description
	}
	if got != "bdca" {
		t.Errorf("Rank order = %q, want bdca", got)
	}
}
