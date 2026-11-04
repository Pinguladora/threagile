package macros

import (
	"bufio"
	"slices"
	"strings"
	"testing"
)

func TestSelectValuesKeepsTheOrderOfTheAnswers(t *testing.T) {
	question := MacroQuestion{PossibleAnswers: []string{"a", "b", "c", "d", "e"}, MultiSelect: true}

	for range 20 {
		got, err := selectValues(question, bufio.NewReader(strings.NewReader("5\n2\n4\n1\n0\n")))
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"a", "b", "d", "e"}; !slices.Equal(got, want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}
