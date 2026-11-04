/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

type ParseAuthorizationTest struct {
	input         string
	expected      Authorization
	expectedError error
}

func TestParseAuthorization(t *testing.T) {
	testCases := map[string]ParseAuthorizationTest{
		"none": {
			input:    "none",
			expected: NoneAuthorization,
		},
		"technical-user": {
			input:    "technical-user",
			expected: TechnicalUser,
		},
		"end-user-identity-propagation": {
			input:    "end-user-identity-propagation",
			expected: EndUserIdentityPropagation,
		},
		"enduser-identity-propagation (legacy spelling)": {
			input:    "enduser-identity-propagation",
			expected: EndUserIdentityPropagation,
		},
		"Enduser-Identity-Propagation (legacy spelling, any case)": {
			input:    "Enduser-Identity-Propagation",
			expected: EndUserIdentityPropagation,
		},
		"unknown": {
			input:         "unknown",
			expectedError: errors.New("unknown authorization value \"unknown\""),
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

// TestLegacyAuthorizationIsNormalised reads the spelling of older releases (threagile#92) and
// writes the current one.
func TestLegacyAuthorizationIsNormalised(t *testing.T) {
	var authorization Authorization
	assert.NoError(t, yaml.Unmarshal([]byte("enduser-identity-propagation"), &authorization))
	assert.Equal(t, EndUserIdentityPropagation, authorization)

	written, err := yaml.Marshal(authorization)
	assert.NoError(t, err)
	assert.Equal(t, "end-user-identity-propagation\n", string(written))

	assert.NoError(t, json.Unmarshal([]byte(`"enduser-identity-propagation"`), &authorization))
	assert.Equal(t, EndUserIdentityPropagation, authorization)
}
