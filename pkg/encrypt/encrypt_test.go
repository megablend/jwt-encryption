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
	params := &Params{
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

func TestParseToken_shouldReturnDecryptedToken(t *testing.T) {
	t.Skip("FIXME: change RSA key to supported type")
	config, configErr := config.New()
	encrypt := New(key.New(config))
	params := &Params{
		Audience: "test/audience",
		Subject:  "test/subject",
		Claims: map[string]interface{}{
			"service": "sample_service",
		},
		Algorithm:      jose.RS256,
		EncyrptionType: key.JWT,
		Ttl:            2000,
	}

	rawToken, _ := encrypt.SignedToken(params)
	claims, err := encrypt.ParseToken(rawToken)

	require.NoError(t, configErr)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
}
