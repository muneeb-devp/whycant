// Package core holds the types shared across whycant's packages.
package core

import (
	"fmt"
	"strings"
)

// Action is what the subject wants to do with the path.
type Action int

// Actions, in the order they are listed in help output.
const (
	Read Action = iota + 1
	Write
	Append
	Exec
	List
	Traverse
	Create
	Delete
)

// Actions lists every action in display order.
var Actions = []Action{Read, Write, Append, Exec, List, Traverse, Create, Delete}

var actionNames = map[Action]string{
	Read:     "read",
	Write:    "write",
	Append:   "append",
	Exec:     "exec",
	List:     "list",
	Traverse: "traverse",
	Create:   "create",
	Delete:   "delete",
}

var actionAliases = map[string]Action{
	"r":     Read,
	"w":     Write,
	"x":     Exec,
	"run":   Exec,
	"ls":    List,
	"cd":    Traverse,
	"mk":    Create,
	"touch": Create,
	"rm":    Delete,
}

// String returns the canonical name, e.g. "read".
func (a Action) String() string {
	if s, ok := actionNames[a]; ok {
		return s
	}
	return fmt.Sprintf("Action(%d)", int(a))
}

// Aliases returns the short names accepted for a, sorted as declared.
func (a Action) Aliases() []string {
	var out []string
	for _, alias := range []string{"r", "w", "x", "run", "ls", "cd", "mk", "touch", "rm"} {
		if actionAliases[alias] == a {
			out = append(out, alias)
		}
	}
	return out
}

// ParseAction accepts a canonical name or alias, case-insensitively.
func ParseAction(s string) (Action, error) {
	s = strings.ToLower(s)
	for a, name := range actionNames {
		if name == s {
			return a, nil
		}
	}
	if a, ok := actionAliases[s]; ok {
		return a, nil
	}
	return 0, fmt.Errorf("unknown action %q (want one of: %s)", s, actionList())
}

func actionList() string {
	names := make([]string, len(Actions))
	for i, a := range Actions {
		names[i] = a.String()
	}
	return strings.Join(names, ", ")
}

// Perm is a set of rwx permission bits, using the same values as the "other"
// class of a mode: R=4, W=2, X=1.
type Perm uint8

// Permission bits.
const (
	PermX Perm = 1 << iota
	PermW
	PermR
)

// String formats p as in a mode string, e.g. "r-x".
func (p Perm) String() string {
	b := []byte("---")
	if p&PermR != 0 {
		b[0] = 'r'
	}
	if p&PermW != 0 {
		b[1] = 'w'
	}
	if p&PermX != 0 {
		b[2] = 'x'
	}
	return string(b)
}

// Short formats only the set bits, e.g. "wx"; used for "need" columns.
func (p Perm) Short() string {
	return strings.ReplaceAll(p.String(), "-", "")
}
