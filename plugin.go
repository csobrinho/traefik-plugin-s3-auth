package plugin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
)

type Config struct {
	AuthorizationHeaderName string       `json:"headerName,omitempty"`
	RemoveHeadersOnSuccess  bool         `json:"removeHeadersOnSuccess,omitempty"`
	StatusCode              int          `json:"statusCode,omitempty"`
	Credentials             []Credential `json:"credentials,omitempty"`
}

type Credential struct {
	AccessKeyID     string `json:"accessKeyId,omitempty"`
	AccessSecretKey string `json:"accessSecretKey,omitempty"`
	Region          string `json:"region,omitempty"`
	Service         string `json:"service,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		AuthorizationHeaderName: "Authorization",
		RemoveHeadersOnSuccess:  false,
		StatusCode:              http.StatusForbidden,
	}
}

type Plugin struct {
	next                    http.Handler
	authorizationHeaderName string
	removeHeadersOnSuccess  bool
	statusCode              int
	credentials             map[string]Credential
	envs                    map[string]string
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
	if config.AuthorizationHeaderName == "" {
		return nil, errors.New("must specify the authorization header name")
	}

	crds := map[string]Credential{}
	for _, cred := range config.Credentials {
		if _, exists := crds[cred.AccessKeyID]; exists {
			return nil, fmt.Errorf("duplicate access key id found: %q", cred.AccessKeyID)
		}
		crds[cred.AccessKeyID] = cred
	}

	data, err := os.ReadFile("/tmp/hello")
	fmt.Fprintf(os.Stderr, "XXX data: %q, err: %v\n", string(data), err)

	envs := map[string]string{}
	// for _, k := range os.Environ() {
	// 	fmt.Println("ENV:", k)
	// 	v, _ := os.LookupEnv(k)
	// 	envs[k] = v
	// }

	return &Plugin{
		next:                    next,
		credentials:             crds,
		authorizationHeaderName: config.AuthorizationHeaderName,
		removeHeadersOnSuccess:  config.RemoveHeadersOnSuccess,
		statusCode:              config.StatusCode,
		envs:                    envs,
	}, nil
}

func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	data, err := os.ReadFile("/tmp/hello")
	fmt.Fprintf(os.Stderr, "XXXX data: %q, err: %v\n", string(data), err)

	err = ValidateHeader(req, p.authorizationHeaderName, p.credentials)
	if err != nil {
		for k, v := range p.envs {
			fmt.Printf("ENV: %s=%s\n", k, v)
		}
		http.Error(rw, http.StatusText(p.statusCode), p.statusCode)
		return
	}

	if p.removeHeadersOnSuccess {
		req.Header.Del(p.authorizationHeaderName)
	}
	p.next.ServeHTTP(rw, req)
}
