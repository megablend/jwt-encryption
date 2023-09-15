package key

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/megablend/jwt-encryption/pkg/config"
	logger "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
)

type Key struct {
	Config *config.Config
}

type SignerType int

func (s SignerType) String() jose.ContentType {
	switch s {
	case JWT:
		return "JWT"
	case JWE:
		return "JWE"
	default:
		return "UNKNOWN"
	}
}

const (
	JWT SignerType = iota
	JWE
)

// PrivateKey returns a private key object from the configured path
func (k *Key) PrivateKey() (*rsa.PrivateKey, error) {
	bytes, err := k.getFileBytes(k.Config.Jwt.Directory, k.Config.Jwt.PrivateKey)
	if err != nil {
		return nil, err
	}

	block, err := k.getBlockBytes(bytes)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(block)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (k *Key) PublicKey() (*rsa.PublicKey, error) {
	bytes, err := k.getFileBytes(k.Config.Jwt.Directory, k.Config.Jwt.PublicKey)
	if err != nil {
		return nil, err
	}

	cert, err := k.parseFromCert(bytes)
	if err != nil {
		return nil, err
	}

	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unable to parse certificate into a private key")
	}
	return key, nil
}

// Signer returns a preferred method of signing token based on the algorithm and type provided
func (k *Key) Signer(headers map[string]string, algorithm jose.SignatureAlgorithm, signerType SignerType) (jose.Signer, error) {
	privateKey, err := k.PrivateKey()
	if err != nil {
		return nil, err
	}

	signerKey := jose.SigningKey{Algorithm: algorithm, Key: privateKey}

	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType(signerType.String())

	// populate custom headers
	if len(headers) > 0 {
		for k, v := range headers {
			signerOpts.WithHeader(jose.HeaderKey(k), v)
		}
	}

	return jose.NewSigner(signerKey, &signerOpts)
}

func (k *Key) getBlockBytes(bytes []byte) ([]byte, error) {
	block, _ := pem.Decode(bytes)
	encrypted := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if encrypted {
		logger.Warn("PEM block is encrypted")
		var err error
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (k *Key) getFileBytes(dir, key string) ([]byte, error) {
	dir, err := k.getBasePath(dir)
	if err != nil {
		return nil, err
	}

	bytes, err := os.ReadFile(fmt.Sprintf("%s/%s", dir, key))
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func (k *Key) parseFromCert(bytes []byte) (*x509.Certificate, error) {
	b, err := k.getBlockBytes(bytes)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(b)
}

func (k *Key) getBasePath(keyPath string) (string, error) {
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		logger.Warn("the configured keys directory does not exist")

		_, fileName, _, ok := runtime.Caller(0)
		if !ok {
			return "", errors.New("failed to retrieve caller information for key path configuration")
		}

		subDir := "pkg/key"
		dir := path.Dir(fileName)
		if !strings.Contains(dir, subDir) {
			return "", errors.New("invalid configuration folder path configured")
		}

		basePath := strings.ReplaceAll(dir, subDir, k.Config.Jwt.Directory)
		// ensure that the final base path is valid
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			return "", errors.New("invalid configuration base path")
		}

		return basePath, nil
	}
	return keyPath, nil
}

func New(config *config.Config) *Key {
	return &Key{
		Config: config,
	}
}
