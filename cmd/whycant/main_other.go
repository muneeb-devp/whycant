//go:build !linux

// Command whycant explains why a user can or cannot access a path.
package main

import (
	"fmt"
	"os"

	"github.com/muneeb-devp/whycant/internal/cli"
)

func main() {
	fmt.Fprintln(os.Stderr, "whycant only supports Linux")
	os.Exit(cli.ExitUsage)
}
