package config

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	logger "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	FILE_NAME = "config.yaml"
	BASE_PATH = "CONFIG_FILE_PATH"
)

var config *Config

type Config struct {
	Jwt struct {
		PrivateKey string `yaml:"private-key"`
		PublicKey  string `yaml:"public-key"`
		Directory  string `yaml:"keys-directory"`
	}
}

func (config *Config) readConfigFile() (*os.File, error) {
	path := fmt.Sprintf("%s/%s", config.getBasePath(), FILE_NAME)
	file, err := os.Open(path)
	if err != nil {
		logger.WithFields(logger.Fields{
			"error": err,
		}).Error("configuration file retrieval failed")
		return nil, err
	}
	return file, nil
}

func (config *Config) getBasePath() string {
	basePath := os.Getenv(BASE_PATH)
	if basePath == "" {
		logger.Errorf("please specify an env variable for %s", BASE_PATH)
	}

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		logger.Warnf("provided base path does not exist")
		_, fileName, _, ok := runtime.Caller(0)
		if !ok {
			logger.Error("missing caller information")
		}
		basePath = strings.ReplaceAll(path.Dir(fileName), "pkg/config", "config")
	}
	return basePath
}

// InitConfig initializes the configuration object with details from the configuration yaml file
func (config *Config) InitConfig() error {
	file, fileErr := config.readConfigFile()
	if fileErr != nil {
		return fileErr
	}

	defer file.Close()

	decoder := yaml.NewDecoder(file)
	err := decoder.Decode(config)
	return err
}

// New parses the yaml file details into a configuration object that can be used throught the lifespan of the application
func New() (*Config, error) {
	if config == nil {
		config = &Config{}
		err := config.InitConfig()
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}
