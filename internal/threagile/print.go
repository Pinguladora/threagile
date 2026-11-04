package threagile

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Pinguladora/threagile"
	"github.com/spf13/cobra"
)

func (what *Threagile) initPrint() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   Print3rdPartyCommand,
		Short: "Print 3rd-party license information",
		Long:  "\n" + Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp) + "\n\n" + ThirdPartyLicenses,
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   PrintLicenseCommand,
		Short: "Print license information",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			appDir, err := cmd.Flags().GetString(appDirFlagName)
			if err != nil {
				cmd.Printf("Unable to read app-dir flag: %v", err)
				return fmt.Errorf("unable to read app-dir flag: %w", err)
			}

			cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
			if appDir != filepath.Clean(appDir) {
				// it is not clear whether this check is still needed
				cmd.Printf("weird app folder %v", appDir)
				return errors.New("weird app folder")
			}

			// A LICENSE.txt in the app folder wins over the one embedded in the binary.
			content, err := threagile.License.ReadFile(filepath.Join(appDir, "LICENSE.txt"))
			if err != nil {
				cmd.Printf("Unable to read license file: %v", err)
				return fmt.Errorf("unable to read license file: %w", err)
			}

			cmd.Print(string(content))
			cmd.Println()

			return nil
		},
	})

	return what
}
