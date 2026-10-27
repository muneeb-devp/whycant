package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/muneeb-devp/whycant/internal/core"
)

// completionCmd prints a shell completion script.
func completionCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: whycant completion <bash|zsh|fish>")
		return ExitUsage
	}
	script, ok := Completion(args[0])
	if !ok {
		fmt.Fprintf(stderr, "whycant: unknown shell %q (want bash, zsh or fish)\n", args[0])
		return ExitUsage
	}
	fmt.Fprint(stdout, script)
	return ExitAllowed
}

// Completion returns the completion script for shell.
func Completion(shell string) (string, bool) {
	var names []string
	for _, a := range core.Actions {
		names = append(names, a.String())
	}
	actions := strings.Join(names, " ")
	switch shell {
	case "bash":
		return strings.ReplaceAll(bashCompletion, "@ACTIONS@", actions), true
	case "zsh":
		return strings.ReplaceAll(zshCompletion, "@ACTIONS@", actions), true
	case "fish":
		return strings.ReplaceAll(fishCompletion, "@ACTIONS@", actions), true
	}
	return "", false
}

const bashCompletion = `# bash completion for whycant
_whycant() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"; prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}"); cword=$COMP_CWORD
    }
    case "$prev" in
        -u|--user) COMPREPLY=($(compgen -u -- "$cur")); return ;;
        -g|--group) COMPREPLY=($(compgen -g -- "$cur")); return ;;
        -p|--pid) COMPREPLY=($(compgen -W "$(ps -eo pid= 2>/dev/null)" -- "$cur")); return ;;
        --color) COMPREPLY=($(compgen -W "auto always never" -- "$cur")); return ;;
        completion) COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur")); return ;;
    esac
    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "-u --user -g --group -p --pid -a --all -v --verbose --json --verify --color -q --quiet -h --help --version" -- "$cur"))
        return
    fi
    local i positional=0
    for ((i = 1; i < cword; i++)); do
        case "${words[i]}" in
            -u|--user|-g|--group|-p|--pid|--color) ((i++)) ;;
            -*) ;;
            *) ((positional++)) ;;
        esac
    done
    if ((positional == 0)); then
        COMPREPLY=($(compgen -W "@ACTIONS@ completion" -- "$cur"))
    else
        COMPREPLY=($(compgen -f -- "$cur"))
        compopt -o filenames 2>/dev/null
    fi
}
complete -F _whycant whycant
`

const zshCompletion = `#compdef whycant
# zsh completion for whycant
_whycant() {
    _arguments -s \
        '(-u --user -p --pid)'{-u,--user}'[check on behalf of this user]:user:_users' \
        '*'{-g,--group}'[also assume membership of this group]:group:_groups' \
        '(-p --pid -u --user -g --group)'{-p,--pid}'[use a running process'"'"'s credentials]:pid:_pids' \
        '(-a --all)'{-a,--all}'[report every problem]' \
        '(-v --verbose)'{-v,--verbose}'[show passing checks]' \
        '(-q --quiet)--json[print JSON]' \
        '--verify[confirm with a real kernel access check]' \
        '--color[when to use color]:when:(auto always never)' \
        '(-q --quiet --json)'{-q,--quiet}'[print only the verdict]' \
        '(- *)'{-h,--help}'[show help]' \
        '(- *)--version[show version]' \
        '1:action:(@ACTIONS@ completion)' \
        '2:path:_files'
}
_whycant "$@"
`

const fishCompletion = `# fish completion for whycant
complete -c whycant -f
complete -c whycant -n '__fish_is_nth_token 1' -a '@ACTIONS@ completion'
complete -c whycant -n '__fish_is_nth_token 2' -F
complete -c whycant -s u -l user -x -a '(__fish_complete_users)' -d 'Check on behalf of this user'
complete -c whycant -s g -l group -x -a '(__fish_complete_groups)' -d 'Also assume this group'
complete -c whycant -s p -l pid -x -a '(__fish_complete_pids)' -d "Use a running process's credentials"
complete -c whycant -s a -l all -d 'Report every problem'
complete -c whycant -s v -l verbose -d 'Show passing checks'
complete -c whycant -l json -d 'Print JSON'
complete -c whycant -l verify -d 'Confirm with a real kernel access check'
complete -c whycant -l color -x -a 'auto always never' -d 'When to use color'
complete -c whycant -s q -l quiet -d 'Print only the verdict'
complete -c whycant -s h -l help -d 'Show help'
complete -c whycant -l version -d 'Show version'
`
