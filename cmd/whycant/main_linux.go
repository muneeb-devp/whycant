//go:build linux

// Command whycant explains why a user can or cannot access a path.
package main

import (
	"os"

	"github.com/muneeb-devp/whycant/internal/cli"
	"github.com/muneeb-devp/whycant/internal/sys"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr, sys.Real{}))
}
