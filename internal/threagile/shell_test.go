package threagile

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompleteCommand(t *testing.T) {
	root := &cobra.Command{Use: "threagile"}
	explain := &cobra.Command{Use: "explain"}
	explain.AddCommand(&cobra.Command{Use: "risk"}, &cobra.Command{Use: "rules"})
	root.AddCommand(explain, &cobra.Command{Use: "execute-model-macro"}, &cobra.Command{Use: "export"},
		&cobra.Command{Use: "secret", Hidden: true})

	for line, want := range map[string]string{
		"exp":           "exp",            // explain and export share no more than that
		"expl":          "explain ",       // one command fits
		"explain r":     "explain r",      // risk and rules
		"explain ru":    "explain rules ", // a subcommand
		"explain ":      "explain r",      // all subcommands
		"ex":            "ex",             // explain, execute-model-macro and export
		"exe":           "execute-model-macro ",
		"nothing ":      "nothing ",         // no such command
		"sec":           "sec",              // hidden commands are not offered
		"  explain  ri": "  explain  risk ", // the spacing stays
	} {
		assert.Equal(t, want, completeCommand(root, line), line)
	}
}

func TestFileHistory(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "history")
	require.NoError(t, os.WriteFile(filename, []byte("first\n\nsecond\nthird\n"), 0o600))

	history := newFileHistory(filename, 3)
	require.Equal(t, 3, history.Len(), "empty lines are left out")
	assert.Equal(t, "third", history.At(0), "the most recent first")

	history.Add("third") // the same as the last one
	history.Add("  ")
	history.Add("fourth")
	assert.Equal(t, 3, history.Len(), "bounded")
	assert.Equal(t, "fourth", history.At(0))
	assert.Equal(t, "second", history.At(2), "the oldest is forgotten")

	again := newFileHistory(filename, 3)
	assert.Equal(t, []string{"second", "third", "fourth"}, again.entries, "it lasts from one session to the next")
}

func TestShellReadsLinesFromAPipe(t *testing.T) {
	s := &shell{lines: bufio.NewScanner(strings.NewReader("list-types\nexplain risk x\n"))}

	first, err := s.readLine()
	require.NoError(t, err)
	assert.Equal(t, "list-types", first)
	second, err := s.readLine()
	require.NoError(t, err)
	assert.Equal(t, "explain risk x", second)
	_, err = s.readLine()
	assert.True(t, errors.Is(err, io.EOF), "the end of the input ends the session")
}
