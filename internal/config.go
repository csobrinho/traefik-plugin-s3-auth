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
	LogLevel    string               `long:"log-level" env:"LOG_LEVEL" default:"warn" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal" choice:"panic" description:"Log level"`
	LogFormat   string               `long:"log-format" env:"LOG_FORMAT" default:"text" choice:"text" choice:"json" choice:"pretty" description:"Log format"`
	Config      func(s string) error `long:"config" env:"CONFIG_FILE" json:"-" description:"Path to config file"`
	Port        int                  `long:"port" env:"PORT" default:"4182" description:"Port to listen on"`
	HeaderName  string               `long:"header-name" env:"HEADER_NAME" default:"Authorization" description:"Name of the authorization header to check"`
	StatusCode  int                  `long:"status-code" env:"STATUS_CODE" default:"401" description:"HTTP status code to return on failure"`
	Credentials []Credential
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
	err := c.parseFlags(args)
	return c, err
}

func (c *Config) parseFlags(args []string) error {
	p := flags.NewParser(c, flags.Default)

	c.Config = func(s string) error {
		b, err := os.ReadFile(s)
		if err != nil {
			return fmt.Errorf("error reading config file: %w", err)
		}
		if err := yaml.Unmarshal(b, &c.Credentials); err != nil {
			return fmt.Errorf("error parsing configYAML: %w", err)
		}
		return nil
	}
	if _, err := p.ParseArgs(args); err != nil {
		return handleFlagError(err)
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
	// Check the authorization header is not empty.
	if c.HeaderName == "" {
		return errors.New("must specify the authorization header name")
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
