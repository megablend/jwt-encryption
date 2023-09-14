package config

import (
	"errors"
	"log"
	"os"
	"testing"

	"github.com/procodr/monkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func patchOsOpen(message string) {
	monkey.Patch(os.Open, func(_ string) (*os.File, error) {
		log.Println("got here")
		return nil, errors.New(message)
	})
}

func TestNew_shouldReturnValidDetails(t *testing.T) {
	cases := []struct {
		name string
	}{
		{"successfully returns valid configuration details"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := os.Setenv(BASE_PATH, "/path/to/config")
			config, configErr := New()

			require.NoError(t, err)
			require.NotNil(t, config)
			assert.NoError(t, configErr)
			assert.EqualValues(t, "private_key.pem", config.Jwt.PrivateKey)
			assert.EqualValues(t, "public_key.pem", config.Jwt.PublicKey)
			assert.EqualValues(t, "config/keys", config.Jwt.Directory)
		})
	}
}

func TestNew_shouldReturnError_whenUnableToReadFile(t *testing.T) {
	errMsg := "test error message while opening file"
	err := os.Setenv(BASE_PATH, "/path/to/config")

	defer monkey.UnpatchAll()
	patchOsOpen(errMsg)

	config, configErr := New()

	require.NoError(t, err)
	require.Nil(t, config)
	assert.Error(t, configErr)
	assert.EqualValues(t, errMsg, configErr.Error())
}
