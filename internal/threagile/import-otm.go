package threagile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/interchange"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/otm"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// yamlIndent is the indentation of the model YAML files that threagile ships.
const yamlIndent = 2

func (what *Threagile) initImportOTM() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ImportOTMCommand,
		Short: "Import an Open Threat Model (OTM) file as a threagile model",
		Long: "\n" + Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp) + "\n\n" +
			"Convert the OTM file named by --" + otmFileFlagName + " (JSON or YAML) into a threagile model: " +
			"trust zones become trust boundaries, components technical assets, dataflows communication links and " +
			"assets data assets. " +
			"Values that threagile needs and OTM has no field for get defaults; review them. Threats are not imported, " +
			"as threagile generates the risks when it analyzes the model.\n\n" +
			"--" + outputFlagName + " names the model file to write when it ends in .yaml or .yml, and else the folder to " +
			"write " + InputFile + " into. An existing file is not overwritten.",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			return what.importOTM(cmd)
		},
	})

	return what
}

func (what *Threagile) importOTM(cmd *cobra.Command) error {
	otmFile := what.config.GetOTMFile()
	if otmFile == "" {
		return fmt.Errorf("no OTM file to import: name it with --%s", otmFileFlagName)
	}

	data, err := os.ReadFile(filepath.Clean(otmFile))
	if err != nil {
		return fmt.Errorf("unable to read the OTM file: %w", err)
	}

	document, err := otm.Parse(data)
	if err != nil {
		return fmt.Errorf("unable to import %q: %w", otmFile, err)
	}

	technologies := make(types.TechnologyMap)
	if err := technologies.LoadWithConfig(what.config, "technologies.yaml"); err != nil {
		return fmt.Errorf("unable to load the technologies: %w", err)
	}
	technologies.PropagateAttributes()

	modelInput, notes := interchange.ToInput(otm.ToInterchange(document), technologies)
	modelInput.ThreagileVersion = ThreagileVersion
	if document.OTMVersion != otm.Version {
		versionNote := fmt.Sprintf("the file is OTM %s, threagile reads OTM %s", document.OTMVersion, otm.Version)
		notes = append([]string{versionNote}, notes...)
	}

	modelYAML, err := importedModelYAML(otmFile, modelInput)
	if err != nil {
		return err
	}

	// make sure the model analyzes before writing it; the analysis does not change the YAML
	progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}
	_, err = model.AnalyzeModel(modelInput, what.config, risks.GetBuiltInRiskRules(), nil, progressReporter)
	if err != nil {
		return fmt.Errorf("the model imported from %q does not analyze: %w", otmFile, err)
	}

	outputFile := importOutputFile(what.config.GetOutputFolder())
	if err := writeNewFile(outputFile, modelYAML); err != nil {
		return err
	}

	printImportSummary(cmd, document, modelInput, outputFile, notes)
	return nil
}

// importedModelYAML is the model YAML file of a model imported from an OTM file.
func importedModelYAML(otmFile string, modelInput *input.Model) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString("# Imported from the Open Threat Model file " + filepath.Base(otmFile) +
		" by threagile " + ImportOTMCommand + ".\n" +
		"# Values that OTM has no field for are threagile's defaults: review them (see docs/otm.md).\n\n")

	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(yamlIndent)
	if err := encoder.Encode(modelInput); err != nil {
		return nil, fmt.Errorf("unable to write the imported model: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("unable to write the imported model: %w", err)
	}

	return buffer.Bytes(), nil
}

// importOutputFile is the model file that --output names, which is a file when it ends in .yaml
// or .yml, and else the folder of a file named like the default model file.
func importOutputFile(output string) string {
	switch strings.ToLower(filepath.Ext(output)) {
	case ".yaml", ".yml":
		return output
	}

	return filepath.Join(output, InputFile)
}

// writeNewFile writes a file that must not exist yet, creating its folder when needed.
func writeNewFile(filename string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0o750); err != nil {
		return fmt.Errorf("unable to create the folder of %q: %w", filename, err)
	}

	file, err := os.OpenFile(filepath.Clean(filename), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%q exists already; name another file or folder with --%s", filename, outputFlagName)
	}
	if err != nil {
		return fmt.Errorf("unable to create %q: %w", filename, err)
	}

	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("unable to write %q: %w", filename, err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("unable to write %q: %w", filename, err)
	}

	return nil
}

func printImportSummary(cmd *cobra.Command, document *otm.Document, modelInput *input.Model,
	outputFile string, notes []string,
) {
	links := 0
	for _, asset := range modelInput.TechnicalAssets {
		links += len(asset.CommunicationLinks)
	}

	threatInstances := 0
	for _, component := range document.Components {
		threatInstances += len(component.Threats)
	}
	for _, dataflow := range document.Dataflows {
		threatInstances += len(dataflow.Threats)
	}

	cmd.Printf("Imported %q into %s: %d trust boundaries, %d technical assets, %d communication links, %d data assets.\n",
		modelInput.Title, outputFile, len(modelInput.TrustBoundaries), len(modelInput.TechnicalAssets), links,
		len(modelInput.DataAssets))
	cmd.Printf("Threats are not imported (%d threats, %d threat instances in the file): "+
		"threagile generates the risks when it analyzes the model.\n", len(document.Threats), threatInstances)

	if len(notes) > 0 {
		cmd.Println("Notes:")
		for _, note := range notes {
			cmd.Println("  - " + note)
		}
	}

	cmd.Printf("Review the defaults in the model, then analyze it: threagile %s --model %s\n",
		AnalyzeModelCommand, outputFile)
}
