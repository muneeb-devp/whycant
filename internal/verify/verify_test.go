package verify

import (
	"testing"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

func TestAccessFor(t *testing.T) {
	tests := []struct {
		action core.Action
		in     string
		path   string
		mode   uint32
	}{
		{core.Read, "/srv/f", "/srv/f", sys.AccessR},
		{core.Append, "/srv/f", "/srv/f", sys.AccessW},
		{core.Traverse, "/srv", "/srv", sys.AccessX},
		{core.Create, "/srv/new", "/srv", sys.AccessW | sys.AccessX},
		{core.Delete, "/tmp/link/../f", "/tmp/link/..", sys.AccessW | sys.AccessX},
		{core.Create, "/top", "/", sys.AccessW | sys.AccessX},
		{core.Delete, "/srv/dir/", "/srv", sys.AccessW | sys.AccessX},
	}
	for _, tt := range tests {
		p, m := AccessFor(tt.action, tt.in)
		if p != tt.path || m != tt.mode {
			t.Errorf("AccessFor(%v, %q) = %q, %d; want %q, %d", tt.action, tt.in, p, m, tt.path, tt.mode)
		}
	}
}
