package traefik_s3_auth_middleware_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	plugin "github.com/csobrinho/traefik-s3-auth-middleware"
)

func setHeaders(t *testing.T, h http.Header) {
	t.Helper()

	h.Set("amz-sdk-invocation-id", "1de9cfea-294b-486c-b973-e31404835327")
	h.Set("amz-sdk-request", "attempt=1; max=3")
	h.Set("content-length", "0")
	h.Set("content-type", "text/markdown; charset=utf-8")
	h.Set("host", "s3.example.com")
	h.Set("x-amz-content-sha256", "c3ab8ff137200000000000000000000000000000000000000000000000000000")
	h.Set("x-amz-date", "20250710T054521Z")
	h.Set("x-amz-meta-ctime", "1752126312.907")
	h.Set("x-amz-meta-mtime", "1752126318.461")
	h.Set("x-amz-user-agent", "aws-sdk-js/3.675.0 ua/2.1 os/macOS#10.15.7 lang/js md/browser#Electron_33.3.2 api/s3#3.675.0 m/E,e")
}

func TestPlugin(t *testing.T) {
	tc := []struct {
		name           string
		crds           []plugin.Credential
		method         string
		authorization  string
		expectedStatus int
		expectedError  plugin.Response
	}{
		{
			name: "valid credentials",
			crds: []plugin.Credential{
				{
					AccessKeyId:     "ACCESS_ACCESS_ACCESS",
					AccessSecretKey: "SECRET12secret123456SECRET12secret123456",
					Region:          "us-east-1",
					Service:         "s3",
				},
			},
			method:         http.MethodGet,
			authorization:  "AWS4-HMAC-SHA256 Credential=ACCESS_ACCESS_ACCESS/20250710/us-east-1/s3/aws4_request, SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-ctime;x-amz-meta-mtime;x-amz-user-agent, Signature=1a9426204df8f5e35f275a2cfd5e5bd70b82fe8893fb7a9cb56154aa43c8e81e",
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid credentials",
			crds: []plugin.Credential{
				{
					AccessKeyId:     "ACCESS_ACCESS_2222AC",
					AccessSecretKey: "SECRET12secret123456SECRET12secret123456",
					Region:          "us-east-1",
					Service:         "s3",
				},
			},
			method:         http.MethodGet,
			authorization:  "AWS4-HMAC-SHA256 Credential=ACCESS_ACCESS_ACCESS/20250710/us-east-1/s3/aws4_request, SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-ctime;x-amz-meta-mtime;x-amz-user-agent, Signature=1a9426204df8f5e35f275a2cfd5e5bd70b82fe8893fb7a9cb56154aa43c8e81e",
			expectedStatus: http.StatusForbidden,
			expectedError: plugin.Response{
				StatusCode: http.StatusForbidden,
				Message:    "invalid S3 authorization. Requests must be properly signed with a valid access id and secret key",
				Error:      "unknown access key id: \"ACCESS_ACCESS_ACCESS\"",
			},
		},
		{
			name: "invalid header",
			crds: []plugin.Credential{
				{
					AccessKeyId:     "ACCESS_ACCESS_2222AC",
					AccessSecretKey: "SECRET12secret123456SECRET12secret123456",
					Region:          "us-east-1",
					Service:         "s3",
				},
			},
			method:         http.MethodGet,
			authorization:  "",
			expectedStatus: http.StatusForbidden,
			expectedError: plugin.Response{
				StatusCode: http.StatusForbidden,
				Message:    "invalid S3 authorization. Requests must be properly signed with a valid access id and secret key",
				Error:      "failed to parse authorization header: empty header",
			},
		},
		{
			name:           "no credentials",
			method:         http.MethodGet,
			authorization:  "",
			expectedStatus: http.StatusForbidden,
			expectedError: plugin.Response{
				StatusCode: http.StatusForbidden,
				Message:    "invalid S3 authorization. Requests must be properly signed with a valid access id and secret key",
				Error:      "must specify at least one valid credential",
			},
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			cfg := plugin.CreateConfig()
			cfg.Credentials = tt.crds

			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

			handler, err := plugin.New(ctx, next, cfg, "s3-plugin")
			if err != nil {
				if tt.expectedError.Error != "" && tt.expectedError.Error == err.Error() {
					// Expected error, so we can skip the test
					return
				}
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, tt.method, "https://s3.example.com/foo/bar/?x=y&z=0", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(cfg.AuthorizationHeaderName, tt.authorization)
			setHeaders(t, req.Header)

			handler.ServeHTTP(recorder, req)
			if recorder.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, recorder.Code)
			}
			b, err := io.ReadAll(recorder.Body)

			if err != nil {
				t.Fatal(err)
			}

			if len(b) > 0 {
				if tt.expectedStatus == http.StatusOK {
					t.Errorf("expected empty body, got %s", b)
				}
				got := plugin.Response{}
				if err := json.Unmarshal(b, &got); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if got.StatusCode != tt.expectedError.StatusCode {
					t.Errorf("expected status code %d, got %d", tt.expectedError.StatusCode, got.StatusCode)
				}
				if got.Message != tt.expectedError.Message {
					t.Errorf("expected message %q, got %q", tt.expectedError.Message, got.Message)
				}
				if got.Error != tt.expectedError.Error {
					t.Errorf("expected error %q, got %q", tt.expectedError.Error, got.Error)
				}
			}
		})
	}
}
