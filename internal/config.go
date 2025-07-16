package tsfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/thomseddon/go-flags"
	"gopkg.in/yaml.v3"
)

var config *Config

// Config holds the runtime application config.
type Config struct {
	Config      func(s string) error `yaml:"-" long:"config" env:"CONFIG_FILE" json:"-" description:"Path to config file"`
	LogLevel    string               `yaml:"logLevel" long:"log-level" env:"LOG_LEVEL" default:"warn" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal" choice:"panic" description:"Log level"`
	LogFormat   string               `yaml:"logFormat" long:"log-format" env:"LOG_FORMAT" default:"text" choice:"text" choice:"json" choice:"pretty" description:"Log format"`
	Port        int                  `yaml:"port" long:"port" env:"PORT" default:"4182" description:"Port to listen on"`
	HeaderName  string               `yaml:"headerName" long:"header-name" env:"HEADER_NAME" default:"Authorization" description:"Name of the authorization header to check"`
	StatusCode  int                  `yaml:"statusCode" long:"status-code" env:"STATUS_CODE" default:"401" description:"HTTP status code to return on failure"`
	Credentials []Credential         `yaml:"credentials"`
}

type Credential struct {
	AccessKeyID     string `json:"accessKeyId"     yaml:"accessKeyId"`
	AccessSecretKey string `json:"accessSecretKey" yaml:"accessSecretKey"`
	Region          string `json:"region"          yaml:"region"`
	Service         string `json:"service"         yaml:"service"`
}

// NewGlobalConfig creates a new global config, parsed from command arguments.
func NewGlobalConfig() *Config {
	var err error
	config, err = NewConfig(os.Args[1:])
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	return config
}

// NewConfig parses and validates provided configuration into a config object.
func NewConfig(args []string) (*Config, error) {
	c := &Config{}
	return c, c.parseFlags(args)
}

func (c *Config) parseFlags(args []string) error {
	p := flags.NewParser(c, flags.Default)

	cf := &Config{}
	c.Config = func(s string) error {
		b, err := os.ReadFile(s)
		if err != nil {
			return fmt.Errorf("error reading config file: %w", err)
		}
		err = yaml.Unmarshal(b, cf)
		if err != nil {
			return fmt.Errorf("error parsing config YAML: %w", err)
		}
		c.Credentials = cf.Credentials
		return nil
	}
	if _, err := p.ParseArgs(args); err != nil {
		return handleFlagError(err)
	}

	// Merge the config file with the command line arguments.
	if cf.LogLevel != "" {
		c.LogLevel = cf.LogLevel
	}
	if cf.LogFormat != "" {
		c.LogFormat = cf.LogFormat
	}
	if cf.Port != 0 {
		c.Port = cf.Port
	}
	if cf.HeaderName != "" {
		c.HeaderName = cf.HeaderName
	}
	if cf.StatusCode != 0 {
		c.StatusCode = cf.StatusCode
	}
	return nil
}

func handleFlagError(err error) error {
	var flagsErr *flags.Error
	if ok := errors.As(err, &flagsErr); ok && flagsErr.Type == flags.ErrHelp {
		// Library has just printed cli help.
		os.Exit(0)
	}
	return err
}

// Validate validates a config object.
func (c *Config) Validate() error {
	// Check for empty credentials.
	if len(c.Credentials) == 0 {
		return errors.New("must specify at least one valid credential")
	}
	for _, cred := range c.Credentials {
		if cred.AccessKeyID == "" || cred.AccessSecretKey == "" {
			return errors.New("must specify both `keyId` and `secretKey` for each credential")
		}

		if cred.Region == "" {
			return errors.New("must specify the region for each credential, eg: `us-east-1`")
		}

		if cred.Service == "" {
			return errors.New("must specify the service for each credential, eg: `s3`")
		}
	}
	if c.HeaderName == "" {
		return errors.New("must specify the authorization header name")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", c.Port)
	}
	if c.StatusCode < 400 || c.StatusCode > 499 {
		return fmt.Errorf("status code must be between 400 and 499, got %d", c.StatusCode)
	}
	return nil
}

func (c *Config) String() string {
	jsonConf, err := json.Marshal(c)
	if err != nil {
		return fmt.Sprintf("error marshaling config: %v", err)
	}
	return string(jsonConf)
}
