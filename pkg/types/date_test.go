package types

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNowUsesSourceDateEpoch(t *testing.T) {
	t.Setenv(sourceDateEpochEnv, "1762214400")

	assert.Equal(t, time.Date(2025, time.November, 4, 0, 0, 0, 0, time.UTC), Now())
}

func TestNowFallsBackToTheCurrentTime(t *testing.T) {
	for name, value := range map[string]string{
		"unset":     "",
		"malformed": "yesterday",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(sourceDateEpochEnv, value) // restores the caller's value afterwards
			if value == "" {
				assert.NoError(t, os.Unsetenv(sourceDateEpochEnv))
			}

			before := time.Now()
			now := Now()

			assert.False(t, now.Before(before), "Now() = %v is before %v", now, before)
			assert.WithinDuration(t, time.Now(), now, time.Minute)
		})
	}
}
