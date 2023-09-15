package key

import (
	"testing"

	"github.com/megablend/jwt-encryption/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestPrivateKey_shouldReturnValidKey(t *testing.T) {
	config, configErr := config.New()
	key := New(config)

	privateKey, keyErr := key.PrivateKey()

	require.NoError(t, configErr)
	assert.NoError(t, keyErr)
	assert.NotNil(t, privateKey)
}

func TestPrivateKey_shouldReturnError(t *testing.T) {
	cases := []struct {
		name   string
		config *config.Config
	}{
		{"when invalid configuration", &config.Config{}},
		{"when configuration with invalid directory", &config.Config{
			Jwt: config.Jwt{
				Directory: "invalid/directory",
			},
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			key := New(testCase.config)

			privateKey, keyErr := key.PrivateKey()

			assert.Error(t, keyErr)
			assert.Nil(t, privateKey)
		})
	}
}

func TestPublicKey_shouldReturnValidKey(t *testing.T) {
	config, configErr := config.New()
	key := New(config)

	publicKey, keyErr := key.PublicKey()

	require.NoError(t, configErr)
	assert.NoError(t, keyErr)
	assert.NotNil(t, publicKey)
}

func TestPublicKey_shouldReturnError(t *testing.T) {
	cases := []struct {
		name   string
		config *config.Config
	}{
		{"when invalid configuration", &config.Config{}},
		{"when configuration with invalid directory", &config.Config{
			Jwt: config.Jwt{
				Directory: "invalid/directory",
			},
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			key := New(testCase.config)

			publicKey, keyErr := key.PublicKey()

			assert.Error(t, keyErr)
			assert.Nil(t, publicKey)
		})
	}
}

func TestSigner_shouldReturnValidSignerObject(t *testing.T) {
	config, configErr := config.New()
	key := New(config)

	signer, signerErr := key.Signer(make(map[string]string), jose.RS256, JWT)

	require.NoError(t, configErr)
	assert.NoError(t, signerErr)
	assert.NotNil(t, signer)
}

func TestSigner_shouldFail_whenUnableToGetPrivateKey(t *testing.T) {
	config := &config.Config{
		Jwt: config.Jwt{
			Directory: "invalid/directory",
		},
	}
	key := New(config)

	signer, signerErr := key.Signer(make(map[string]string), jose.RS256, JWT)

	assert.Error(t, signerErr)
	assert.Nil(t, signer)
}
