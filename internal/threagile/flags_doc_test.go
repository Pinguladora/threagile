package threagile

import (
	"flag"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// updateDocs rewrites docs/flags.md from the flags of the commands: go test ./internal/threagile -update.
var updateDocs = flag.Bool("update", false, "rewrite docs/flags.md")

const flagsDocFile = "../../docs/flags.md"

// TestFlagsDocMatchesCommands keeps docs/flags.md in line with the flags the commands take.
func TestFlagsDocMatchesCommands(t *testing.T) {
	root := new(Threagile).initRoot().initImport().initImportOTM().initAnalyze().initCreate().initExecute().
		initExplain().initList().initPrint().initQuit().initServer().initVersion().rootCmd

	got := flagsDoc(root)
	if *updateDocs {
		require.NoError(t, os.WriteFile(flagsDocFile, []byte(got), 0o600))
		return
	}
	want, err := os.ReadFile(flagsDocFile)
	require.NoError(t, err)
	assert.Equal(t, string(want), got, "docs/flags.md is out of date, run the test with -update")
}

// flagsDoc renders the flags of the root command, which every command takes, and those of the commands that
// take more, as Markdown tables.
func flagsDoc(root *cobra.Command) string {
	var doc strings.Builder
	doc.WriteString("# Flags\n\n")
	doc.WriteString("<!-- Generated from the commands by `go test ./internal/threagile -update`; do not edit. -->\n\n")
	doc.WriteString("Every flag can also be set in the [config file](./config.md). Every command takes these flags:\n\n")
	writeFlagTable(&doc, root.PersistentFlags())

	commands := root.Commands()
	slices.SortFunc(commands, func(a, b *cobra.Command) int { return strings.Compare(a.Name(), b.Name()) })
	for _, command := range commands {
		if !command.HasAvailablePersistentFlags() && !command.HasAvailableLocalFlags() {
			continue
		}
		own := pflag.NewFlagSet(command.Name(), pflag.ContinueOnError)
		command.PersistentFlags().VisitAll(own.AddFlag)
		command.LocalNonPersistentFlags().VisitAll(own.AddFlag)
		if !own.HasFlags() {
			continue
		}
		doc.WriteString("\n`" + command.Name() + "` also takes:\n\n")
		writeFlagTable(&doc, own)
	}
	return doc.String()
}

func writeFlagTable(doc *strings.Builder, flags *pflag.FlagSet) {
	doc.WriteString("| Flag | Type | Default | Description |\n|------|------|---------|-------------|\n")
	flags.VisitAll(func(f *pflag.Flag) {
		name := "`--" + f.Name + "`"
		if f.Shorthand != "" {
			name += ", `-" + f.Shorthand + "`"
		}
		defaultValue := ""
		if f.DefValue != "" && f.DefValue != "[]" {
			defaultValue = "`" + f.DefValue + "`"
		}
		doc.WriteString("| " + name + " | " + f.Value.Type() + " | " + defaultValue + " | " +
			strings.ReplaceAll(f.Usage, "|", "\\|") + " |\n")
	})
}
