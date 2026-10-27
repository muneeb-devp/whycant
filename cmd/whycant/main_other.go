//go:build !linux

// Command whycant explains why a user can or cannot access a path.
package main

import (
	"fmt"
	"os"

	"github.com/muneeb-devp/whycant/internal/cli"
)

func main() {
	// Completions are plain text and work anywhere, so packaging can
	// generate them on any build machine.
	if len(os.Args) == 3 && os.Args[1] == "completion" {
		if script, ok := cli.Completion(os.Args[2]); ok {
			fmt.Print(script)
			return
		}
	}
	fmt.Fprintln(os.Stderr, "whycant only supports Linux")
	os.Exit(cli.ExitUsage)
}
