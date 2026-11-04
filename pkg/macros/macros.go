/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package macros

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
	"gopkg.in/yaml.v3"
)

type Macros interface {
	GetMacroDetails() MacroDetails
	GetNextQuestion(model *types.Model) (nextQuestion MacroQuestion, err error)
	ApplyAnswer(questionID string, answer ...string) (message string, validResult bool, err error)
	GoBack() (message string, validResult bool, err error)
	GetFinalChangeImpact(
		modelInput *input.Model, model *types.Model,
	) (changes []string, message string, validResult bool, err error)
	Execute(modelInput *input.Model, model *types.Model) (message string, validResult bool, err error)
}

func ListBuiltInMacros() []Macros {
	return []Macros{
		NewBuildPipeline(),
		NewAddVault(),
		NewPrettyPrint(),
		newRemoveUnusedTags(),
		NewSeedRiskTracking(),
		NewSeedTags(),
	}
}

func ListCustomMacros() []Macros {
	// custom macros are not supported yet
	return []Macros{}
}

func GetMacroByID(id string) (Macros, error) {
	allMacros := slices.Concat(ListBuiltInMacros(), ListCustomMacros())
	for _, macro := range allMacros {
		if macro.GetMacroDetails().ID == id {
			return macro, nil
		}
	}
	return nil, fmt.Errorf("unknown macro id: %v", id)
}

func ExecuteModelMacro(modelInput *input.Model, inputFile string, parsedModel *types.Model, macroID string) error {
	macros, err := GetMacroByID(macroID)
	if err != nil {
		return err
	}

	printMacroHeader(macros.GetMacroDetails())
	reader := bufio.NewReader(os.Stdin)
	quit, err := askQuestions(macros, parsedModel, reader)
	if err != nil || quit {
		return err
	}

	return confirmAndExecute(macros, modelInput, inputFile, parsedModel, reader)
}

func printMacroHeader(macroDetails MacroDetails) {
	fmt.Println("Executing model macro:", macroDetails.ID)
	fmt.Println()
	fmt.Println()
	printBorder(len(macroDetails.Title), true)
	fmt.Println(macroDetails.Title)
	printBorder(len(macroDetails.Title), true)
	if len(macroDetails.Description) > 0 {
		fmt.Println(macroDetails.Description)
	}
	fmt.Println()
}

// askQuestions asks the questions of the macro until it has no more; it reports whether the user quit.
func askQuestions(macros Macros, parsedModel *types.Model, reader *bufio.Reader) (bool, error) {
	for {
		nextQuestion, err := macros.GetNextQuestion(parsedModel)
		if err != nil {
			return false, fmt.Errorf("unable to get the next question: %w", err)
		}
		if nextQuestion.NoMoreQuestions() {
			return false, nil
		}

		quit, err := askQuestion(macros, nextQuestion, reader)
		if err != nil || quit {
			return quit, err
		}
	}
}

// askQuestion asks a question and applies the answer, or goes back for the answer BACK; it reports whether
// the user quit.
func askQuestion(macros Macros, question MacroQuestion, reader *bufio.Reader) (bool, error) {
	printQuestion(question)

	if question.IsValueConstrained() && question.MultiSelect {
		resultingMultiValueSelection, err := selectValues(question, reader)
		if err != nil {
			return false, err
		}
		message, validResult, _ := macros.ApplyAnswer(question.ID, resultingMultiValueSelection...)
		printAnswerResult(message, validResult)
		return false, nil
	}

	if question.IsValueConstrained() {
		printChoices(question)
	}
	answer, err := readAnswer(question, reader)
	if err != nil {
		return false, err
	}

	message := ""
	validResult := true
	switch {
	case strings.ToLower(answer) == "quit":
		fmt.Println("Quitting without executing the model macro")
		return true, nil
	case strings.ToLower(answer) == "back":
		message, validResult, _ = macros.GoBack()
	case len(answer) > 0: // individual answer
		if !question.IsMatchingValueConstraint(answer) {
			fmt.Println()
			fmt.Println(">>> INVALID <<<")
			fmt.Println("Answer does not match any allowed value. Please try again:")
			return false, nil
		}
		message, validResult, _ = macros.ApplyAnswer(question.ID, answer)
	}
	printAnswerResult(message, validResult)
	return false, nil
}

func printQuestion(question MacroQuestion) {
	fmt.Println()
	printBorder(len(question.Title), false)
	fmt.Println(question.Title)
	printBorder(len(question.Title), false)
	if len(question.Description) > 0 {
		fmt.Println(question.Description)
	}
}

func printAnswerResult(message string, validResult bool) {
	if !validResult {
		fmt.Println()
		fmt.Println(">>> INVALID <<<")
	}
	fmt.Println(message)
	fmt.Println()
}

// firstTwoDigitNumber is the first number of a list of answers that does not get padded to two digits.
const firstTwoDigitNumber = 10

func numberPadding(number int) string {
	if number < firstTwoDigitNumber {
		return " "
	}
	return ""
}

// selectValues lets the user select and deselect the answers of a multi-select question until they are done.
func selectValues(question MacroQuestion, reader *bufio.Reader) ([]string, error) {
	selectedValues := make(map[string]bool)
	for {
		printSelection(question, selectedValues)
		answer, err := readLine(reader)
		if err != nil {
			return nil, err
		}
		val, err := strconv.Atoi(answer)
		if err != nil {
			continue
		}
		if val == 0 {
			resultingMultiValueSelection := make([]string, 0)
			for key, selected := range selectedValues {
				if selected {
					resultingMultiValueSelection = append(resultingMultiValueSelection, key)
				}
			}
			return resultingMultiValueSelection, nil
		}
		if val > 0 && val <= len(question.PossibleAnswers) { // flip selection
			selectedValues[question.PossibleAnswers[val-1]] = !selectedValues[question.PossibleAnswers[val-1]]
		}
	}
}

func printSelection(question MacroQuestion, selectedValues map[string]bool) {
	fmt.Println("Please select (multiple executions possible) from the following values (use number to select/deselect):")
	fmt.Println("    0:", "SELECTION PROCESS FINISHED: CONTINUE TO NEXT QUESTION")
	for i, val := range question.PossibleAnswers {
		number := i + 1
		selected := " "
		if val, exists := selectedValues[val]; exists && val {
			selected = "*"
		}
		fmt.Println(" "+selected+" "+numberPadding(number)+strconv.Itoa(number)+":", val)
	}
	fmt.Println()
	fmt.Print("Enter number to select/deselect (or 0 when finished): ")
}

func printChoices(question MacroQuestion) {
	fmt.Println("Please choose from the following values (enter value directly or use number):")
	for i, val := range question.PossibleAnswers {
		number := i + 1
		fmt.Println("   "+numberPadding(number)+strconv.Itoa(number)+":", val)
	}
}

// readAnswer reads the answer to a question that is not a multi-select one: an empty answer takes the
// default, and a number picks one of the possible answers.
func readAnswer(question MacroQuestion, reader *bufio.Reader) (string, error) {
	fmt.Println()
	fmt.Println("Enter your answer (use 'BACK' to go one step back or 'QUIT' to quit without executing the model macro)")
	fmt.Print("Answer")
	if len(question.DefaultAnswer) > 0 {
		fmt.Print(" (default '" + question.DefaultAnswer + "')")
	}
	fmt.Print(": ")
	answer, err := readLine(reader)
	if err != nil {
		return "", err
	}
	if len(answer) == 0 && len(question.DefaultAnswer) > 0 { // accepting the default
		return question.DefaultAnswer, nil
	}
	if question.IsValueConstrained() { // convert number to value
		if val, err := strconv.Atoi(answer); err == nil && val > 0 && val <= len(question.PossibleAnswers) {
			return question.PossibleAnswers[val-1], nil
		}
	}
	return answer, nil
}

// readLine reads a line of input without its line break.
func readLine(reader *bufio.Reader) (string, error) {
	answer, err := reader.ReadString('\n')
	// convert CRLF to LF
	answer = strings.TrimSpace(strings.ReplaceAll(answer, "\n", ""))
	if err != nil {
		return answer, fmt.Errorf("unable to read the answer: %w", err)
	}
	return answer, nil
}

// confirmAndExecute shows the changes the macro would make and asks whether to make them, until the user
// says yes or no.
func confirmAndExecute(
	macros Macros, modelInput *input.Model, inputFile string, parsedModel *types.Model, reader *bufio.Reader,
) error {
	for {
		fmt.Println()
		fmt.Println()
		fmt.Println("#################################################################")
		fmt.Println("Do you want to execute the model macro (updating the model file)?")
		fmt.Println("#################################################################")
		fmt.Println()
		fmt.Println("The following changes will be applied:")

		changes, message, validResult, err := macros.GetFinalChangeImpact(modelInput, parsedModel)
		if err != nil {
			return fmt.Errorf("unable to get the changes of the model macro: %w", err)
		}
		for _, change := range changes {
			fmt.Println(" -", change)
		}
		if !validResult {
			fmt.Println()
			fmt.Println(">>> INVALID <<<")
		}
		fmt.Println()
		fmt.Println(message)
		fmt.Println()
		fmt.Print("Apply these changes to the model file?\nType Yes or No: ")
		answer, err := readLine(reader)
		if err != nil {
			return err
		}
		answer = strings.ToLower(answer)
		fmt.Println()

		switch answer {
		case "yes", "y":
			return executeMacro(macros, modelInput, inputFile, parsedModel)

		case "no", "n":
			fmt.Println("Quitting without executing the model macro")
			return nil
		}
	}
}

// executeMacro makes the changes of the macro and writes the model file, after backing it up.
func executeMacro(macros Macros, modelInput *input.Model, inputFile string, parsedModel *types.Model) error {
	message, validResult, err := macros.Execute(modelInput, parsedModel)
	if err != nil {
		return fmt.Errorf("unable to apply the changes of the model macro: %w", err)
	}
	if !validResult {
		fmt.Println()
		fmt.Println(">>> INVALID <<<")
	}
	fmt.Println(message)
	fmt.Println()
	backupFilename := inputFile + ".backup"
	// the backup goes next to the model file rather than into a random file in /dev/shm
	fmt.Println("Creating backup model file:", backupFilename)
	_, err = copyFile(inputFile, backupFilename)
	if err != nil {
		return err
	}
	fmt.Println("Updating model")
	yamlBytes, err := yaml.Marshal(modelInput)
	if err != nil {
		return fmt.Errorf("unable to encode the model: %w", err)
	}
	/*
		yamlBytes = model.ReformatYAML(yamlBytes)
	*/
	fmt.Println("Writing model file:", inputFile)
	err = os.WriteFile(inputFile, yamlBytes, 0o400)
	if err != nil {
		return fmt.Errorf("unable to write the model file: %w", err)
	}
	fmt.Println("Model file successfully updated")
	return nil
}

func printBorder(length int, bold bool) {
	char := "-"
	if bold {
		char = "="
	}
	for i := 1; i <= length; i++ {
		fmt.Print(char)
	}
	fmt.Println()
}

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, fmt.Errorf("unable to check the file to copy: %w", err)
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(filepath.Clean(src))
	if err != nil {
		return 0, fmt.Errorf("unable to open the file to copy: %w", err)
	}
	defer func() { _ = source.Close() }()

	destination, err := os.Create(filepath.Clean(dst))
	if err != nil {
		return 0, fmt.Errorf("unable to create the copy: %w", err)
	}
	defer func() { _ = destination.Close() }()
	nBytes, err := io.Copy(destination, source)
	if err != nil {
		return nBytes, fmt.Errorf("unable to copy the file: %w", err)
	}
	return nBytes, nil
}

type MacroDetails struct {
	ID, Title, Description string
}

type MacroQuestion struct {
	ID, Title, Description string
	PossibleAnswers        []string
	MultiSelect            bool
	DefaultAnswer          string
}

const NoMoreQuestionsID = ""

// changesetValid is the message macros report when their final change set is valid.
const changesetValid = "Changeset valid"

// The messages of the macros for answers and for going back.
const (
	answerProcessed     = "Answer processed"
	cannotGoBackFurther = "Cannot go back further"
)

// The answers of the yes-or-no questions of the macros.
const (
	answerYes = "Yes"
	answerNo  = "No"
)

// The IDs of the questions about trust boundaries that the macros ask.
const (
	withinTrustBoundaryQuestion   = "within-trust-boundary"
	selectedTrustBoundaryQuestion = "selected-trust-boundary"
)

// productNameDescription describes the questions for the product a technical asset is.
const productNameDescription = "This name affects the technical asset's title and ID plus also the tags used."

// The IDs of the data assets that the macros add.
const (
	sourcecodeDataAsset           = "sourcecode"
	deploymentDataAsset           = "deployment"
	configurationSecretsDataAsset = "configuration-secrets"
)

func NoMoreQuestions() MacroQuestion {
	return MacroQuestion{
		ID:              NoMoreQuestionsID,
		Title:           "",
		Description:     "",
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "",
	}
}

func (what MacroQuestion) NoMoreQuestions() bool {
	return what.ID == NoMoreQuestionsID
}

func (what MacroQuestion) IsValueConstrained() bool {
	return len(what.PossibleAnswers) > 0
}

func (what MacroQuestion) IsMatchingValueConstraint(answer string) bool {
	if what.IsValueConstrained() {
		for _, val := range what.PossibleAnswers {
			if strings.EqualFold(val, answer) {
				return true
			}
		}
		return false
	}
	return true
}
