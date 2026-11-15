package model

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"

	"go.yaml.in/yaml/v4"
)

// runner runs the plugin of a custom risk rule; it could move to an internal package.
type runner struct {
	Filename    string
	Parameters  []string
	In          any
	Out         any
	ErrorOutput string
}

func (p *runner) Load(filename string) (*runner, error) {
	*p = runner{
		Filename: filename,
	}

	fileInfo, statError := os.Stat(filename)
	if statError != nil {
		return p, fmt.Errorf("error checking plugin file: %w", statError)
	}

	if !fileInfo.Mode().IsRegular() {
		return p, fmt.Errorf("run %q is not a regular file", filename)
	}

	return p, nil
}

func (p *runner) Run(in any, out any, parameters ...string) error {
	*p = runner{
		Filename:   p.Filename,
		Parameters: parameters,
		In:         in,
		Out:        out,
	}

	// the plugin runs until it exits: nothing cancels it
	plugin := exec.CommandContext(context.Background(), p.Filename, p.Parameters...) // #nosec G204
	stdin, stdinError := plugin.StdinPipe()
	if stdinError != nil {
		return fmt.Errorf("error connecting input data: %w", stdinError)
	}
	defer func() { _ = stdin.Close() }()

	var stdoutBuf bytes.Buffer
	plugin.Stdout = &stdoutBuf

	var stderrBuf bytes.Buffer
	plugin.Stderr = &stderrBuf

	startError := plugin.Start()
	if startError != nil {
		return fmt.Errorf("error starting plugin: %w", startError)
	}

	inData, inError := yaml.Marshal(p.In)
	if inError != nil {
		return fmt.Errorf("error encoding input data: %w", inError)
	}

	_, writeError := stdin.Write(inData)
	if writeError != nil {
		return fmt.Errorf("error writing input data: %w", writeError)
	}

	inCloseError := stdin.Close()
	if inCloseError != nil {
		return fmt.Errorf("error closing input data: %w", inCloseError)
	}

	waitError := plugin.Wait()
	p.ErrorOutput = stderrBuf.String()
	if waitError != nil {
		return fmt.Errorf("%w: %v", waitError, p.ErrorOutput)
	}

	stdout := stdoutBuf.Bytes()
	unmarshalError := yaml.Unmarshal(stdout, p.Out)
	if unmarshalError != nil {
		return fmt.Errorf("error decoding output data: %w", unmarshalError)
	}

	// _ = os.WriteFile(fmt.Sprintf("%v.yaml", rand.Int31()), stdout, 0644)

	return nil
}
