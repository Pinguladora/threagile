package types

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.yaml.in/yaml/v4"
)

func TestParseIdentity(t *testing.T) {
	testCases := map[string]struct {
		input         string
		expected      Identity
		expectedError error
	}{
		"empty (not modelled)":    {input: "", expected: NoneIdentity},
		"none":                    {input: "none", expected: NoneIdentity},
		"service-account":         {input: "service-account", expected: ServiceAccount},
		"workload":                {input: "workload", expected: Workload},
		"end-user":                {input: "end-user", expected: EndUser},
		"technical-user (legacy)": {input: "technical-user", expected: ServiceAccount},
		"end-user-identity-propagation (legacy)": {
			input: "end-user-identity-propagation", expected: EndUser,
		},
		"Enduser-Identity-Propagation (legacy spelling, any case)": {
			input: "Enduser-Identity-Propagation", expected: EndUser,
		},
		"unknown": {input: "admin", expectedError: errors.New("unknown identity value \"admin\"")},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseIdentity(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}

// TestLegacyIdentityIsNormalised reads the spelling of older releases (threagile#92) and the values that the
// authorization of earlier versions of the model held, and writes the current ones.
func TestLegacyIdentityIsNormalised(t *testing.T) {
	var identity Identity
	assert.NoError(t, yaml.Unmarshal([]byte("enduser-identity-propagation"), &identity))
	assert.Equal(t, EndUser, identity)

	written, err := yaml.Marshal(identity)
	assert.NoError(t, err)
	assert.Equal(t, "end-user\n", string(written))

	assert.NoError(t, json.Unmarshal([]byte(`"technical-user"`), &identity))
	assert.Equal(t, ServiceAccount, identity)
}

func TestLegacyIdentity(t *testing.T) {
	for authorization, want := range map[string]Identity{
		"none": NoneIdentity, "None": NoneIdentity, "technical-user": ServiceAccount,
		"end-user-identity-propagation": EndUser, "enduser-identity-propagation": EndUser,
	} {
		identity, ok := LegacyIdentity(authorization)
		assert.True(t, ok, authorization)
		assert.Equal(t, want, identity, authorization)
	}
	for _, authorization := range []string{"", "object-level", "service-account"} {
		_, ok := LegacyIdentity(authorization)
		assert.False(t, ok, authorization)
	}
}
