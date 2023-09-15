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

// A param allows calling methods to provide the required details for the encryption
type Param struct {
	Audience       string
	Subject        string
	Claims         map[string]interface{}
	Headers        map[string]string
	Algorithm      jose.SignatureAlgorithm
	EncyrptionType key.SignerType
	Ttl            uint
}

// SignedToken returns the JWT encrypted token using the RSA keys provided in the configuraiton
// It takes the parameter argument which provides details of the issuer, subject, headers and claims
// As part of the parameters you are required to provide the encryption type whihc is either JWT or JWE
func (e *Encrypt) SignedToken(param *Param) (string, error) {
	// valdiate the details for the provided params
	if valid, err := e.isValidParams(param); !valid {
		return "", err
	}

	// create a signer with the configured RSA keys
	signer, err := e.key.Signer(param.Headers, param.Algorithm, param.EncyrptionType)
	if err != nil {
		return "", err
	}

	builder := e.buildClaims(param, signer)
	return builder.CompactSerialize()
}

// isValidParams ensures that the provided params are valid before usage
func (e *Encrypt) isValidParams(params *Param) (bool, error) {
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

// ParseToken decrypts/parse the provided raw token signed using the configured RSA keys
func (e *Encrypt) ParseToken(token string) (map[string]interface{}, error) {
	parsedToken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}

	// retrieve the public key from the private key
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

// isTokenExpired ensures that a token is not expired
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

func (e *Encrypt) buildClaims(param *Param, signer jose.Signer) jwt.Builder {
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

// New returns a new encryption object
func New(key *key.Key) *Encrypt {
	return &Encrypt{
		key: key,
	}
}
