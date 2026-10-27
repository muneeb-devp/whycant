// Package cli parses arguments, wires the packages together and maps the
// outcome to an exit code.
package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/pflag"

	"github.com/muneeb-devp/whycant/internal/checks"
	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/engine"
	"github.com/muneeb-devp/whycant/internal/identity"
	"github.com/muneeb-devp/whycant/internal/report"
	"github.com/muneeb-devp/whycant/internal/sys"
	"github.com/muneeb-devp/whycant/internal/walk"
)

// Exit codes; see the README.
const (
	ExitAllowed        = 0
	ExitDenied         = 1
	ExitUsage          = 2
	ExitIndeterminate  = 3
	ExitVerifyMismatch = 4
)

// Build information, set with -ldflags at release time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Options is the parsed command line.
type Options struct {
	Action  core.Action
	Path    string
	User    string   // name or uid; empty means the current uid
	Groups  []string // extra groups to assume, names or gids
	PID     int      // 0 when unset
	All     bool
	Verbose bool
	JSON    bool
	Verify  bool
	Quiet   bool
	Color   string // auto, always, never
}

// errHelp and errVersion end parsing successfully.
var (
	errHelp    = errors.New("help requested")
	errVersion = errors.New("version requested")
)

// Main runs whycant with args (excluding the program name) and returns the
// exit code.
func Main(args []string, stdout, stderr io.Writer, s sys.System) int {
	opts, err := Parse(args)
	switch {
	case errors.Is(err, errHelp):
		fmt.Fprint(stdout, usage())
		return ExitAllowed
	case errors.Is(err, errVersion):
		fmt.Fprintf(stdout, "whycant %s (commit %s, built %s)\n", Version, Commit, Date)
		return ExitAllowed
	case err != nil:
		fmt.Fprintf(stderr, "whycant: %v\nRun 'whycant --help' for usage.\n", err)
		return ExitUsage
	}

	if err := notYet(opts); err != nil {
		fmt.Fprintf(stderr, "whycant: %v\n", err)
		return ExitUsage
	}

	names := identity.NewResolver(s)
	subject, err := names.Subject(opts.User, opts.Groups)
	if err != nil {
		fmt.Fprintf(stderr, "whycant: %v\n", err)
		return ExitUsage
	}
	nodes, err := walk.Walk(s, opts.Action, opts.Path)
	if err != nil {
		fmt.Fprintf(stderr, "whycant: %v\n", err)
		return ExitUsage
	}
	for _, n := range nodes {
		if n.Exists {
			n.OwnerName = names.UserName(n.Info.UID)
			n.GroupName = names.GroupName(n.Info.GID)
		}
	}

	invoker := s.Getuid()
	ctx := &checks.Context{
		Sys:         s,
		Subject:     subject,
		Action:      opts.Action,
		Names:       names,
		InvokerUID:  invoker,
		InvokerName: names.UserName(invoker),
		Argv:        append([]string{"whycant"}, args...),
	}
	result := engine.Run(ctx, nodes, checks.Default(), opts.All)
	if abs, err := walk.Abs(s, opts.Path); err == nil {
		result.Path = abs // as the user named it, before symlinks
	}
	if err := report.Human(stdout, result, report.Options{Verbose: opts.Verbose, Quiet: opts.Quiet}); err != nil {
		fmt.Fprintf(stderr, "whycant: %v\n", err)
	}

	switch result.Verdict {
	case core.Denied:
		return ExitDenied
	case core.Indeterminate:
		return ExitIndeterminate
	}
	return ExitAllowed
}

// notYet rejects options whose milestone has not landed, rather than
// silently ignoring them.
func notYet(opts Options) error {
	switch {
	case opts.JSON:
		return errors.New("--json is not implemented yet")
	case opts.PID != 0:
		return errors.New("--pid is not implemented yet")
	case opts.Verify:
		return errors.New("--verify is not implemented yet")
	}
	return nil
}

// Parse turns args into Options. It returns errHelp or errVersion when those
// flags are given.
func Parse(args []string) (Options, error) {
	var opts Options
	fs := pflag.NewFlagSet("whycant", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var help, version bool
	fs.StringVarP(&opts.User, "user", "u", "", "")
	fs.StringArrayVarP(&opts.Groups, "group", "g", nil, "")
	fs.IntVarP(&opts.PID, "pid", "p", 0, "")
	fs.BoolVarP(&opts.All, "all", "a", false, "")
	fs.BoolVarP(&opts.Verbose, "verbose", "v", false, "")
	fs.BoolVar(&opts.JSON, "json", false, "")
	fs.BoolVar(&opts.Verify, "verify", false, "")
	fs.StringVar(&opts.Color, "color", "auto", "")
	fs.BoolVarP(&opts.Quiet, "quiet", "q", false, "")
	fs.BoolVarP(&help, "help", "h", false, "")
	fs.BoolVar(&version, "version", false, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return opts, errHelp
		}
		return opts, err
	}
	if help {
		return opts, errHelp
	}
	if version {
		return opts, errVersion
	}

	switch opts.Color {
	case "auto", "always", "never":
	default:
		return opts, fmt.Errorf("--color must be auto, always or never, not %q", opts.Color)
	}
	if fs.Changed("pid") && opts.PID <= 0 {
		return opts, fmt.Errorf("--pid must be a positive process id")
	}
	if opts.PID != 0 && (opts.User != "" || len(opts.Groups) > 0) {
		return opts, errors.New("--pid cannot be combined with --user or --group")
	}
	if opts.JSON && opts.Quiet {
		return opts, errors.New("--json and --quiet cannot be combined")
	}

	rest := fs.Args()
	if len(rest) != 2 {
		return opts, fmt.Errorf("expected <action> <path>, got %d argument(s)", len(rest))
	}
	action, err := core.ParseAction(rest[0])
	if err != nil {
		return opts, err
	}
	if rest[1] == "" {
		return opts, errors.New("path must not be empty")
	}
	opts.Action = action
	opts.Path = rest[1]
	return opts, nil
}

func usage() string {
	var actions strings.Builder
	for _, a := range core.Actions {
		fmt.Fprintf(&actions, "  %-9s", a)
		if aliases := a.Aliases(); len(aliases) > 0 {
			fmt.Fprintf(&actions, " (%s)", strings.Join(aliases, ", "))
		}
		actions.WriteByte('\n')
	}
	return `whycant explains why a user can or cannot access a path on Linux.

Usage:
  whycant [flags] <action> <path>

Actions:
` + actions.String() + `
Flags:
  -u, --user <name|uid>    check on behalf of this user (default: the current uid)
  -g, --group <name|gid>   also assume membership of this group (repeatable)
  -p, --pid <pid>          use a running process's credentials
  -a, --all                report every problem, not just the first blocker
  -v, --verbose            show passing checks and extra detail
      --json               print JSON instead of text
      --verify             confirm the result with a real kernel access check (root only)
      --color <when>       auto, always or never (default auto; honors NO_COLOR)
  -q, --quiet              print only the verdict line
  -h, --help               show this help
      --version            show version information

Use -- before a path that starts with a dash.

Exit codes:
  0 allowed, 1 denied, 2 usage error, 3 could not determine, 4 verify mismatch
`
}
