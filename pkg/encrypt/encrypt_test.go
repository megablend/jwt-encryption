package encrypt

import (
	"strings"
	"testing"

	"github.com/megablend/jwt-encryption/pkg/config"
	"github.com/megablend/jwt-encryption/pkg/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestSignedToken_shouldReturnValidToken(t *testing.T) {
	config, configErr := config.New()
	encrypt := New(key.New(config))
	params := &Param{
		Audience: "test/audience",
		Subject:  "test/subject",
		Claims: map[string]interface{}{
			"service": "sample_service",
		},
		Algorithm:      jose.RS256,
		EncyrptionType: key.JWT,
		Ttl:            2000,
	}

	token, err := encrypt.SignedToken(params)

	require.NoError(t, configErr)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.True(t, len(strings.Split(token, ".")) == 3)
}

func TestSignedToken_shouldReturnError(t *testing.T) {
	cases := []struct {
		name   string
		config *config.Config
		params *Param
	}{
		{"when missing audience", &config.Config{}, &Param{
			Subject: "test/subject",
		}},
		{"when missing subject", &config.Config{}, &Param{
			Audience: "test/audience",
		}},
		{"when missing algorithm", &config.Config{}, &Param{
			Audience: "test/audience",
			Subject:  "test/subject",
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			encrypt := New(key.New(testCase.config))

			token, err := encrypt.SignedToken(testCase.params)

			assert.Error(t, err)
			assert.Empty(t, token)
		})
	}
}

func TestSignedToken_shouldReturnError_whenInvalidConfig(t *testing.T) {
	encrypt := New(key.New(&config.Config{}))
	params := &Param{
		Audience: "test/audience",
		Subject:  "test/subject",
		Claims: map[string]interface{}{
			"service": "sample_service",
		},
		Algorithm:      jose.RS256,
		EncyrptionType: key.JWT,
		Ttl:            2000,
	}

	token, err := encrypt.SignedToken(params)

	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestParseToken_shouldReturnDecryptedToken(t *testing.T) {
	config, configErr := config.New()
	encrypt := New(key.New(config))
	params := &Param{
		Audience: "test/audience",
		Subject:  "test/subject",
		Claims: map[string]interface{}{
			"service": "sample_service",
		},
		Algorithm:      jose.RS256,
		EncyrptionType: key.JWT,
		Ttl:            2000,
	}

	rawToken, signerErr := encrypt.SignedToken(params)
	claims, err := encrypt.ParseToken(rawToken)

	require.NoError(t, signerErr)
	require.NoError(t, configErr)
	require.NotNil(t, rawToken)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
}
