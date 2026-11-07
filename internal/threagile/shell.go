package threagile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// historyLimit is how many lines the history of the interactive mode keeps.
const historyLimit = 1000

// shellPrompt is the prompt of the interactive mode, in red.
const shellPrompt = "\033[31m>>\033[0m "

// shell reads the lines of the interactive mode: with line editing, history and completion of the commands on a
// terminal, and line by line from anything else, such as a pipe.
type shell struct {
	terminal *term.Terminal
	lines    *bufio.Scanner
	fd       int
	state    *term.State // the terminal's own mode, which commands run in
}

// newShell sets up the line reader of the interactive mode; it reports why it could not.
func (what *Threagile) newShell() (*shell, bool) {
	fd := int(os.Stdin.Fd()) // #nosec G115 -- a file descriptor fits an int
	if !term.IsTerminal(fd) {
		return &shell{lines: bufio.NewScanner(os.Stdin)}, true
	}

	dir, homeError := os.UserHomeDir()
	if homeError != nil {
		what.rootCmd.Println("Error, please report bug at https://github.com/Threagile/threagile. " +
			"Unable to find home directory: " + homeError.Error())
		return nil, false
	}
	state, stateError := term.GetState(fd)
	if stateError != nil {
		what.rootCmd.Println("Unable to read the terminal mode: " + stateError.Error())
		return nil, false
	}

	for _, child := range what.rootCmd.Commands() {
		what.useUsage(child)
	}
	terminal := term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}, shellPrompt)
	terminal.History = newFileHistory(filepath.Join(dir, ".threagile_history"), historyLimit)
	terminal.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		if key != '\t' {
			return "", 0, false
		}
		completed := completeCommand(what.rootCmd, line[:pos])
		return completed + line[pos:], len(completed), completed != line[:pos]
	}
	return &shell{terminal: terminal, fd: fd, state: state}, true
}

// readLine reads the next line; io.EOF ends the session, on Ctrl-C and Ctrl-D too.
func (s *shell) readLine() (string, error) {
	if s.terminal == nil {
		if s.lines.Scan() {
			return s.lines.Text(), nil
		}
		return "", errors.Join(io.EOF, s.lines.Err())
	}
	if _, err := term.MakeRaw(s.fd); err != nil {
		return "", fmt.Errorf("unable to set up the terminal: %w", err)
	}
	defer func() { _ = term.Restore(s.fd, s.state) }() // the command of the line prints in the usual mode
	line, err := s.terminal.ReadLine()
	if err != nil {
		return "", fmt.Errorf("unable to read a line: %w", err)
	}
	return line, nil
}

// useUsage sets the usage of the command and of its subcommands, which their help and the completion show.
func (what *Threagile) useUsage(cmd *cobra.Command) {
	cmd.SetUsageTemplate(UsageTemplate)
	cmd.Use = what.usage(cmd)
	for _, child := range cmd.Commands() {
		what.useUsage(child)
	}
}

// completeCommand completes the last word of the line to the names of the commands that can come there: to the name
// when only one fits, else as far as all that fit agree.
func completeCommand(root *cobra.Command, line string) string {
	words := strings.Fields(line)
	partial := ""
	if len(words) > 0 && !strings.HasSuffix(line, " ") {
		partial, words = words[len(words)-1], words[:len(words)-1]
	}
	command := subcommand(root, words)
	if command == nil {
		return line
	}
	names := make([]string, 0)
	for _, child := range command.Commands() {
		if !child.Hidden && strings.HasPrefix(child.Name(), partial) {
			names = append(names, child.Name())
		}
	}
	if len(names) == 0 {
		return line
	}
	completion := commonPrefix(names)
	if len(names) == 1 {
		completion += " "
	}
	return line[:len(line)-len(partial)] + completion
}

// subcommand is the command that the words name, starting from the root, or nil when they name none.
func subcommand(root *cobra.Command, words []string) *cobra.Command {
	command := root
	for _, word := range words {
		next := slices.IndexFunc(command.Commands(), func(child *cobra.Command) bool { return child.Name() == word })
		if next < 0 {
			return nil
		}
		command = command.Commands()[next]
	}
	return command
}

// commonPrefix is the longest start that all the names share.
func commonPrefix(names []string) string {
	prefix := names[0]
	for _, name := range names[1:] {
		for !strings.HasPrefix(name, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	return prefix
}

// fileHistory is the history of the interactive mode, kept in a file of one line each, the oldest first, so that it
// lasts from one session to the next. It forgets the oldest lines beyond its limit.
type fileHistory struct {
	filename string
	limit    int
	entries  []string // the oldest first
}

func newFileHistory(filename string, limit int) *fileHistory {
	history := &fileHistory{filename: filename, limit: limit}
	if data, err := os.ReadFile(filepath.Clean(filename)); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if strings.TrimSpace(line) != "" {
				history.entries = append(history.entries, line)
			}
		}
	}
	history.trim()
	return history
}

func (h *fileHistory) Add(entry string) {
	if strings.TrimSpace(entry) == "" || h.Len() > 0 && h.At(0) == entry {
		return
	}
	h.entries = append(h.entries, entry)
	h.trim()
	// the history only helps, so a file that cannot be written does not stop the session
	_ = os.WriteFile(filepath.Clean(h.filename), []byte(strings.Join(h.entries, "\n")+"\n"), 0o600)
}

func (h *fileHistory) Len() int { return len(h.entries) }

// At returns an entry, 0 being the most recent one.
func (h *fileHistory) At(index int) string { return h.entries[len(h.entries)-1-index] }

func (h *fileHistory) trim() {
	if len(h.entries) > h.limit {
		h.entries = h.entries[len(h.entries)-h.limit:]
	}
}
