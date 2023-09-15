package encrypt

import (
	"errors"
	"strings"
	"time"

	"github.com/megablend/jwt-encryption/pkg/key"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Encrypt struct {
	key *key.Key
}

type Params struct {
	Audience       string
	Subject        string
	Claims         map[string]interface{}
	Headers        map[string]string
	Algorithm      jose.SignatureAlgorithm
	EncyrptionType key.SignerType
	Ttl            uint
}

func (e *Encrypt) SignedToken(param *Params) (string, error) {
	if valid, err := e.isValidParams(param); !valid {
		return "", err
	}

	signer, err := e.key.Signer(param.Headers, param.Algorithm, param.EncyrptionType)
	if err != nil {
		return "", err
	}

	builder := e.buildClaims(param, signer)
	return builder.CompactSerialize()
}

func (e *Encrypt) isValidParams(params *Params) (bool, error) {
	if params.Audience == "" || len(strings.TrimSpace(params.Audience)) == 0 {
		return false, errors.New("invalid audience provided")
	}

	if params.Subject == "" || len(strings.TrimSpace(params.Subject)) == 0 {
		return false, errors.New("invalid subject provided")
	}

	if params.Algorithm == "" {
		return false, errors.New("invalid alogrithm provided")
	}

	return true, nil
}

func (e *Encrypt) ParseToken(token string) (map[string]interface{}, error) {
	parsedToken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}

	claims := make(map[string]interface{})
	key, err := e.key.PrivateKey()
	if err != nil {
		return nil, err
	}

	err = parsedToken.Claims(&key.PublicKey, &claims)
	if err != nil {
		return nil, err
	}

	// check if the token has expired
	if expired, err := e.isTokenExpired(claims); expired {
		return nil, err
	}
	return claims, nil
}

func (e *Encrypt) isTokenExpired(claims map[string]interface{}) (bool, error) {
	expiry, exists := claims["exp"]
	if !exists || expiry == nil {
		return true, errors.New("missing expiration key in token parsed claim")
	}

	convertedExp := expiry.(float64)
	exp := time.Unix(int64(convertedExp), 0)
	if expired := exp.UTC().Before(time.Now().UTC()); expired {
		return true, errors.New("token has expired")
	}

	return false, nil
}

func (e *Encrypt) buildClaims(param *Params, signer jose.Signer) jwt.Builder {
	builder := jwt.Signed(signer)
	builderClaims := jwt.Claims{
		Issuer:   param.Audience,
		Subject:  param.Subject,
		Audience: jwt.Audience{param.Audience},
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Duration(param.Ttl) * time.Millisecond)),
	}

	return builder.Claims(builderClaims).Claims(param.Claims)
}

func New(key *key.Key) *Encrypt {
	return &Encrypt{
		key: key,
	}
}
