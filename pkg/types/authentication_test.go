/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseAuthenticationTest struct {
	input         string
	expected      Authentication
	expectedError error
}

func TestParseAuthentication(t *testing.T) {
	testCases := map[string]ParseAuthenticationTest{
		"none": {
			input:    "none",
			expected: NoneAuthentication,
		},
		"credentials": {
			input:    "credentials",
			expected: Credentials,
		},
		"session-id": {
			input:    "session-id",
			expected: SessionId,
		},
		"token": {
			input:    "token",
			expected: Token,
		},
		"client-certificate": {
			input:    "client-certificate",
			expected: ClientCertificate,
		},
		"short-lived-token": {
			input:    "short-lived-token",
			expected: ShortLivedToken,
		},
		"long-lived-token": {
			input:    "long-lived-token",
			expected: LongLivedToken,
		},
		"multi-factor": {
			input:    "multi-factor",
			expected: MultiFactor,
		},
		"two-factor (earlier name)": {
			input:    "two-factor",
			expected: MultiFactor,
		},
		"externalized": {
			input:    "externalized",
			expected: Externalized,
		},
		"unknown": {
			input:         "unknown",
			expectedError: errors.New("unknown authentication value \"unknown\""),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseAuthentication(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
