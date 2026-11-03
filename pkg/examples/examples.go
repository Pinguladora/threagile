/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package examples

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Pinguladora/threagile"
)

// The functions below write the example model, the stub model and the editing
// support files into outputDir. Each file comes from appFolder when that folder
// holds a copy (the upstream image's /app layout, where inputFile is a fallback
// name for the models), and from the copy embedded in the binary otherwise.

func CreateExampleModelFile(appFolder, outputDir, inputFile string) error {
	return writeAsset(threagile.ExampleModel, filepath.Join(outputDir, "threagile-example-model.yaml"),
		filepath.Join(appFolder, "threagile-example-model.yaml"), filepath.Join(appFolder, inputFile))
}

func CreateStubModelFile(appFolder, outputDir, inputFile string) error {
	return writeAsset(threagile.StubModel, filepath.Join(outputDir, "threagile-stub-model.yaml"),
		filepath.Join(appFolder, "threagile-stub-model.yaml"), filepath.Join(appFolder, inputFile))
}

func CreateEditingSupportFiles(appFolder, outputDir string) error {
	schemaError := writeAsset(threagile.Schema, filepath.Join(outputDir, "schema.json"),
		filepath.Join(appFolder, "schema.json"))
	if schemaError != nil {
		return schemaError
	}

	return writeAsset(threagile.LiveTemplates, filepath.Join(outputDir, "live-templates.txt"),
		filepath.Join(appFolder, "live-templates.txt"))
}

func writeAsset(asset threagile.Asset, dst string, overrides ...string) error {
	data, err := asset.ReadFile(overrides...)
	if err != nil {
		return fmt.Errorf("unable to read %v: %w", asset, err)
	}

	destination, err := os.Create(filepath.Clean(dst))
	if err != nil {
		return fmt.Errorf("unable to create %q: %w", dst, err)
	}

	_, writeError := destination.Write(data)
	closeError := destination.Close()
	if err := errors.Join(writeError, closeError); err != nil {
		return fmt.Errorf("unable to write %q: %w", dst, err)
	}

	return nil
}
