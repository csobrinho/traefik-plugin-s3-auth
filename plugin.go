package traefik_plugin_s3_auth //nolint:revive,nolintlint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Config struct {
	HeaderName  string        `json:"headerName,omitempty"`
	StatusCode  int           `json:"statusCode,omitempty"`
	Credentials []*Credential `json:"credentials,omitempty"`
}

type Credential struct {
	AccessKeyID     string `json:"accessKeyId,omitempty"`
	AccessSecretKey string `json:"accessSecretKey,omitempty"`
	Region          string `json:"region,omitempty"`
	Service         string `json:"service,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		HeaderName: "Authorization",
		StatusCode: http.StatusForbidden,
	}
}

type Plugin struct {
	next        http.Handler
	headerName  string
	statusCode  int
	credentials []*Credential
	Now         func() time.Time
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("Creating plugin: %s instance: %+v, ctx: %+v\n", name, *config, ctx)

	// Check for empty credentials.
	if len(config.Credentials) == 0 {
		return nil, errors.New("must specify at least one valid credential")
	}
	for _, cred := range config.Credentials {
		if cred.AccessKeyID == "" || cred.AccessSecretKey == "" {
			return nil, errors.New("must specify both `keyId` and `secretKey` for each credential")
		}
		if cred.Region == "" {
			return nil, errors.New("must specify the region for each credential, eg: `us-east-1`")
		}
		if cred.Service == "" {
			return nil, errors.New("must specify the service for each credential, eg: `s3`")
		}
	}
	// Check the authorization header is not empty.
	if config.HeaderName == "" {
		return nil, errors.New("must specify the authorization header name")
	}
	return &Plugin{
		next:        next,
		credentials: config.Credentials,
		headerName:  config.HeaderName,
		statusCode:  config.StatusCode,
		Now:         time.Now,
	}, nil
}

func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if err := validateHeader(req, p.headerName, p.credentials, p.Now()); err != nil {
		fmt.Printf("%q header validation failed: %v\n", p.headerName, err)
		http.Error(rw, http.StatusText(p.statusCode), p.statusCode)
		return
	}

	p.next.ServeHTTP(rw, req)
}
