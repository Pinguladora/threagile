package threagile

import (
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/server"
	"github.com/spf13/cobra"
)

func (what *Threagile) initServer() *Threagile {
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Run server",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			return what.runServer()
		},
	}

	what.rootCmd.AddCommand(serverCmd)

	return what
}

func (what *Threagile) runServer() error {
	what.config.SetServerMode(true)
	serverError := what.config.CheckServerFolder()
	if serverError != nil {
		return serverError
	}

	server.RunServer(what.config, risks.GetBuiltInRiskRules())
	return nil
}
