/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseAuthorizationTest struct {
	input         string
	expected      Authorization
	expectedError error
}

func TestParseAuthorization(t *testing.T) {
	testCases := map[string]ParseAuthorizationTest{
		"empty (not modelled)": {
			input:    "",
			expected: UnknownAuthorization,
		},
		"unknown": {
			input:    "unknown",
			expected: UnknownAuthorization,
		},
		"none": {
			input:    "none",
			expected: NoneAuthorization,
		},
		"authenticated-only": {
			input:    "authenticated-only",
			expected: AuthenticatedOnly,
		},
		"function-level": {
			input:    "function-level",
			expected: FunctionLevel,
		},
		"Object-Level (any case)": {
			input:    "Object-Level",
			expected: ObjectLevel,
		},
		"technical-user (an identity now)": {
			input:         "technical-user",
			expectedError: errors.New("unknown authorization value \"technical-user\""),
		},
		"rbac": {
			input:         "rbac",
			expectedError: errors.New("unknown authorization value \"rbac\""),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseAuthorization(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
