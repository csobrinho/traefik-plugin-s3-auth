package traefik_s3_auth_middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Config struct {
	Credentials             []Credential `json:"credentials,omitempty"`
	AuthorizationHeaderName string       `json:"headerName,omitempty"`
	RemoveHeadersOnSuccess  bool         `json:"removeHeadersOnSuccess,omitempty"`
}

type Credential struct {
	AccessKeyId     string `json:"accessKeyId,omitempty"`
	AccessSecretKey string `json:"accessSecretKey,omitempty"`
	Region          string `json:"region,omitempty"`
	Service         string `json:"service,omitempty"`
}

type Response struct {
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		AuthorizationHeaderName: "Authorization",
		RemoveHeadersOnSuccess:  false,
	}
}

type Plugin struct {
	next                    http.Handler
	credentials             map[string]Credential
	authorizationHeaderName string
	removeHeadersOnSuccess  bool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("Creating plugin: %s instance: %+v, ctx: %+v\n", name, *config, ctx)

	// Check for empty credentials.
	if len(config.Credentials) == 0 {
		return nil, fmt.Errorf("must specify at least one valid credential")
	}
	for _, cred := range config.Credentials {
		if cred.AccessKeyId == "" || cred.AccessSecretKey == "" {
			return nil, fmt.Errorf("must specify both `keyId` and `secretKey` for each credential")
		}
		if cred.Region == "" {
			return nil, fmt.Errorf("must specify the region for each credential, eg: `us-east-1`")
		}
		if cred.Service == "" {
			return nil, fmt.Errorf("must specify the service for each credential, eg: `s3`")
		}
	}
	// Check the authorization header is not empty.
	if config.AuthorizationHeaderName == "" {
		return nil, fmt.Errorf("must specify the authorization header name")
	}
	crds := map[string]Credential{}
	for _, cred := range config.Credentials {
		if _, exists := crds[cred.AccessKeyId]; exists {
			return nil, fmt.Errorf("duplicate access key id found: %q", cred.AccessKeyId)
		}
		crds[cred.AccessKeyId] = cred
	}

	return &Plugin{
		next:                    next,
		credentials:             crds,
		authorizationHeaderName: config.AuthorizationHeaderName,
		removeHeadersOnSuccess:  config.RemoveHeadersOnSuccess,
	}, nil
}

func (ka *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	err := ValidateHeader(req, ka.authorizationHeaderName, ka.credentials)
	if err == nil {
		if ka.removeHeadersOnSuccess {
			req.Header.Del(ka.authorizationHeaderName)
		}
		ka.next.ServeHTTP(rw, req)

		return
	}
	response := Response{
		Message:    "invalid S3 authorization. Requests must be properly signed with a valid access id and secret key",
		StatusCode: http.StatusForbidden,
		Error:      err.Error(),
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(response.StatusCode)
	if err := json.NewEncoder(rw).Encode(response); err != nil {
		fmt.Printf("error when sending response to an invalid S3 authorization: %s", err.Error())
	}
}
