package threagile

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/spf13/cobra"
)

func (what *Threagile) initMigrate() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   MigrateModelCommand,
		Short: "Rewrite a model of an earlier version to the current fields",
		Long: "\n" + Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp) + "\n\n" +
			"Rewrite the model file named by --" + inputFileFlagName + ", and the files it includes, in place: the " +
			"identity that the authorization of a communication link held (none, technical-user or " +
			"end-user-identity-propagation) moves into its identity, leaving its authorization unknown, and " +
			"two-factor authentication becomes multi-factor. Only the changed lines are rewritten, so comments and " +
			"layout stay. The command lists what it changed and what to review by hand, like the authorization of " +
			"the migrated links and links authenticated with token, which may be short-lived-token or " +
			"long-lived-token.",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			return what.migrateModel(cmd)
		},
	})

	return what
}

func (what *Threagile) migrateModel(cmd *cobra.Command) error {
	migration, err := model.MigrateModelFile(what.config.GetInputFile())
	if err != nil {
		return fmt.Errorf("unable to migrate the model: %w", err)
	}

	if len(migration.Changes) == 0 {
		cmd.Println("Nothing to migrate.")
	}
	for _, change := range migration.Changes {
		cmd.Println("changed:", change)
	}
	for _, note := range migration.Notes {
		cmd.Println("review: ", note)
	}
	return nil
}
