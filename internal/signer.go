package tsfa

// Adapted from https://github.com/bluecatengineering/traefik-aws-plugin/blob/main/signer/signer.go

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func ValidateHeader(req *http.Request, headerName string, creds []Credential) error {
	h := req.Header.Get(headerName)

	// First check if the header can be parsed.
	a, err := ParseHeader(h)
	if err != nil {
		return fmt.Errorf("failed to parse authorization header: %w", err)
	}
	var cred *Credential
	for _, c := range creds {
		if c.AccessKeyID == a.AccessKeyID && c.Region == a.Region && c.Service == a.Service {
			cred = &c
			break
		}
	}
	if cred == nil {
		return fmt.Errorf("unknown access key id: %q, region: %q, service: %q", a.AccessKeyID, a.Region, a.Service)
	}

	q, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return fmt.Errorf("failed to parse query parameters: %w", err)
	}
	qp := map[string]string{}
	for k, v := range q {
		qp[k] = strings.Join(v, ",")
	}

	sh := map[string]string{}
	for _, k := range a.SignedHeaders {
		v, ok := resolveValue(k, req, req.Header)
		if !ok {
			return fmt.Errorf("missing signed header: %q", k)
		}
		sh[k] = v
	}

	s3 := &s3request{
		cred:          *cred,
		method:        req.Method,
		uri:           req.URL.Path,
		date:          a.Date,
		queryParams:   qp,
		signedHeaders: sh,
	}

	// Then try to recreate the authorization header.
	newa := s3.Sign()
	if nh, nhs := newa.ToString(""), newa.ToString(" "); h != nh && h != nhs {
		for k, v := range sh {
			log.Debugf("Signed header[%q]: %q\n", k, v)
		}
		return fmt.Errorf("signature mismatch expected: %q got: %q", nhs, h)
	}

	// Signature is valid.
	return nil
}

func resolveValue(name string, req *http.Request, h http.Header) (string, bool) {
	switch strings.ToLower(name) {
	case "host":
		return req.Host, true
	case "method":
		return req.Method, true
	case "content-length":
		return strconv.FormatInt(req.ContentLength, 10), true
	default:
		v := h.Values(name)
		if v == nil {
			v = h.Values(strings.ToLower(name))
		}
		if v == nil {
			return "", false
		}
		return strings.Join(v, ", "), len(v) > 0
	}
}

type Authorization struct {
	Algo          string
	AccessKeyID   string
	Date          string
	Region        string
	Service       string
	SignedHeaders []string
	Signature     string
}

func (a Authorization) ToString(pad string) string {
	return "AWS4-HMAC-" + a.Algo + " " +
		"Credential=" + a.AccessKeyID + "/" + a.Date + "/" + a.Region + "/" + a.Service + "/aws4_request" +
		"," + pad + "SignedHeaders=" + strings.Join(a.SignedHeaders, ";") +
		"," + pad + "Signature=" + a.Signature
}

func ParseHeader(header string) (Authorization, error) {
	var empty Authorization
	if header == "" {
		return empty, errors.New("empty header")
	}
	matches := regexHeader.FindStringSubmatch(header)
	if len(matches) != regexHeaderGroups {
		return empty, errors.New("invalid header format")
	}
	names := regexHeader.SubexpNames()
	matched := map[string]string{}
	for i, match := range matches {
		if i > 0 && names[i] != "" {
			matched[names[i]] = match
		}
	}
	if matched["Algo"] != "SHA256" {
		return empty, fmt.Errorf("unsupported algorithm: %q", matched["Algo"])
	}
	for _, key := range []string{"AccessKeyId", "Date", "Region", "Service", "SignedHeaders", "Signature"} {
		if matched[key] == "" {
			return empty, fmt.Errorf("missing header: %q", key)
		}
	}

	return Authorization{
		Algo:          matched["Algo"],
		AccessKeyID:   matched["AccessKeyId"],
		Date:          matched["Date"],
		Region:        matched["Region"],
		Service:       matched["Service"],
		SignedHeaders: strings.Split(matched["SignedHeaders"], ";"),
		Signature:     matched["Signature"],
	}, nil
}

var regexHeader = regexp.MustCompile(`^AWS4-HMAC-(?P<Algo>SHA256)\s*Credential=(?P<AccessKeyId>.*)\/(?P<Date>[0-9]{8})\/(?P<Region>.*)\/(?P<Service>.*)\/aws4_request\,\s*SignedHeaders=(?P<SignedHeaders>.*),\s*Signature=(?P<Signature>.*)$`)

const regexHeaderGroups = 8

// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
type s3request struct {
	cred          Credential
	method        string
	date          string
	queryParams   map[string]string
	signedHeaders map[string]string
	uri           string
}

// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#create-canonical-request
func (s *s3request) RequestString() string {
	queryString := canonString(s.queryParams, "=", "&", true)
	headers := canonString(s.signedHeaders, ":", "\n", false)
	signedHeaders := strings.Join(sortedKeys(s.signedHeaders), ";")
	hashedPayload := s.signedHeaders["x-amz-content-sha256"]

	return fmt.Sprintf("%s\n%s\n%s\n%s\n\n%s\n%s", s.method, s.uri, queryString, headers, signedHeaders, hashedPayload)
}

// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#create-string-to-sign
func (s *s3request) StringToSignV4() string {
	algorithm := "AWS4-HMAC-SHA256"

	requestDateTime := s.date
	if amzDate, ok := s.signedHeaders["x-amz-date"]; ok {
		requestDateTime = amzDate
	}

	credentialScope := requestDateTime[:8] + "/" + s.cred.Region + "/" + s.cred.Service + "/aws4_request"

	sha := sha256.New()
	sha.Write([]byte(s.RequestString()))
	canonRequestSha := sha.Sum(nil)
	hashedCanonRequest := hex.EncodeToString(canonRequestSha)

	return fmt.Sprintf("%s\n%s\n%s\n%s", algorithm, requestDateTime, credentialScope, hashedCanonRequest)
}

// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#calculate-signature
func (s *s3request) SignatureV4() string {
	date := s.date
	if amzDate, ok := s.signedHeaders["x-amz-date"]; ok {
		date = amzDate
	}

	dateKey := hmac.New(sha256.New, []byte("AWS4"+s.cred.AccessSecretKey))
	dateKey.Write([]byte(date[:8]))

	dateRegionKey := hmac.New(sha256.New, dateKey.Sum(nil))
	dateRegionKey.Write([]byte(s.cred.Region))

	dateRegionServiceKey := hmac.New(sha256.New, dateRegionKey.Sum(nil))
	dateRegionServiceKey.Write([]byte(s.cred.Service))

	signingKey := hmac.New(sha256.New, dateRegionServiceKey.Sum(nil))
	signingKey.Write([]byte("aws4_request"))

	signatureV4 := hmac.New(sha256.New, signingKey.Sum(nil))
	signatureV4.Write([]byte(s.StringToSignV4()))

	return hex.EncodeToString(signatureV4.Sum(nil))
}

// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html#add-signature-to-request
func (s *s3request) Sign() Authorization {
	date := s.date
	if amzDate, ok := s.signedHeaders["x-amz-date"]; ok {
		date = amzDate
	}
	return Authorization{
		Algo:          "SHA256",
		AccessKeyID:   s.cred.AccessKeyID,
		Date:          date[:8],
		Region:        s.cred.Region,
		Service:       s.cred.Service,
		SignedHeaders: sortedKeys(s.signedHeaders),
		Signature:     s.SignatureV4(),
	}
}

func canonString(in map[string]string, sep string, inter string, encoding bool) string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var c string
	for _, k := range keys {
		if c != "" {
			c += inter
		}
		if encoding {
			c += fmt.Sprintf("%s%s%s", url.QueryEscape(k), sep, url.QueryEscape(in[k]))
		} else {
			c += fmt.Sprintf("%s%s%s", k, sep, in[k])
		}
	}
	return c
}

func sortedKeys(in map[string]string) []string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	return keys
}
