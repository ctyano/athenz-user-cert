package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseJWTNumericDate(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    int64
		wantErr bool
	}{
		{name: "float64", input: float64(1234), want: 1234},
		{name: "json number", input: json.Number("5678"), want: 5678},
		{name: "int64", input: int64(42), want: 42},
		{name: "int", input: int(99), want: 99},
		{name: "string", input: "77", want: 77},
		{name: "non integer float", input: float64(1.5), wantErr: true},
		{name: "unsupported", input: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseJWTNumericDate(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseJWTNumericDate returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
		})
	}
}

func TestCreateCacheDirCreatesAndReusesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")

	if err := createCacheDir(dir, false); err != nil {
		t.Fatalf("createCacheDir returned error: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("expected directory to exist: %v", err)
	}

	if err := createCacheDir(dir, true); err != nil {
		t.Fatalf("createCacheDir returned error for existing directory: %v", err)
	}
}

func TestGetOIDCDiscovery(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		return jsonResponse(http.StatusOK, `{"authorization_endpoint":"https://issuer.example/auth","token_endpoint":"https://issuer.example/token"}`), nil
	})
	defer restore()

	originalIssuer := DEFAULT_OIDC_ISSUER
	DEFAULT_OIDC_ISSUER = "stub://issuer.example"
	t.Cleanup(func() {
		DEFAULT_OIDC_ISSUER = originalIssuer
	})

	debug := false
	authURL, tokenURL, err := GetOIDCDiscovery(&debug)
	if err != nil {
		t.Fatalf("GetOIDCDiscovery returned error: %v", err)
	}
	if authURL != "https://issuer.example/auth" {
		t.Fatalf("expected authorization endpoint, got %q", authURL)
	}
	if tokenURL != "https://issuer.example/token" {
		t.Fatalf("expected token endpoint, got %q", tokenURL)
	}
}

func TestGetOIDCDiscoveryRejectsMissingEndpoints(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"authorization_endpoint":"https://issuer.example/auth"}`), nil
	})
	defer restore()

	originalIssuer := DEFAULT_OIDC_ISSUER
	DEFAULT_OIDC_ISSUER = "stub://issuer.example"
	t.Cleanup(func() {
		DEFAULT_OIDC_ISSUER = originalIssuer
	})

	debug := false
	if _, _, err := GetOIDCDiscovery(&debug); err == nil {
		t.Fatal("expected discovery without token endpoint to return an error")
	}
}

func TestBuildPKCEOAuthConfig(t *testing.T) {
	conf, err := buildPKCEOAuthConfig("https://issuer.example/auth", "https://issuer.example/token")
	if err != nil {
		t.Fatalf("buildPKCEOAuthConfig returned error: %v", err)
	}
	if conf.State == "" || conf.CodeVerifier == "" || conf.CodeChallenge == "" {
		t.Fatalf("expected PKCE config to populate state and verifier fields: %#v", conf)
	}

	sum := sha256.Sum256([]byte(conf.CodeVerifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if conf.CodeChallenge != wantChallenge {
		t.Fatalf("expected code challenge %q, got %q", wantChallenge, conf.CodeChallenge)
	}
}

func TestExchangeAuthCodeWritesCachedAccessToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/x-www-form-urlencoded") {
			t.Fatalf("expected form content type, got %q", got)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("failed to parse form body: %v", err)
		}
		if values.Get("code") != "test-code" {
			t.Fatalf("expected auth code, got %q", values.Get("code"))
		}
		if values.Get("client_secret") != "secret" {
			t.Fatalf("expected client secret, got %q", values.Get("client_secret"))
		}
		if values.Get("code_verifier") != "verifier" {
			t.Fatalf("expected code verifier, got %q", values.Get("code_verifier"))
		}

		return jsonResponse(http.StatusOK, `{"access_token":"fresh-token"}`), nil
	})
	defer restore()

	conf := &oauthConfig{
		ClientID:     "client-id",
		ClientSecret: "secret",
		RedirectURL:  "http://127.0.0.1:8080",
		TokenURL:     "stub://issuer.example/token",
		CodeVerifier: "verifier",
	}

	got, err := exchangeAuthCode(conf, "test-code")
	if err != nil {
		t.Fatalf("exchangeAuthCode returned error: %v", err)
	}
	if got != "fresh-token" {
		t.Fatalf("expected access token, got %q", got)
	}

	cachedToken, err := os.ReadFile(getAccessTokenCachePath())
	if err != nil {
		t.Fatalf("failed to read cached access token: %v", err)
	}
	if string(cachedToken) != "fresh-token" {
		t.Fatalf("expected cached access token, got %q", string(cachedToken))
	}
}

func TestGetPasswordGrantAccessTokenWritesCachedAccessToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			return jsonResponse(http.StatusOK, `{"authorization_endpoint":"https://issuer.example/auth","token_endpoint":"stub://issuer.example/token"}`), nil
		case "/token":
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", r.Method)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatalf("failed to parse form body: %v", err)
			}
			if values.Get("grant_type") != "password" {
				t.Fatalf("expected password grant, got %q", values.Get("grant_type"))
			}
			if values.Get("username") != "dex-user" || values.Get("password") != "secret" {
				t.Fatalf("unexpected credentials %q/%q", values.Get("username"), values.Get("password"))
			}
			if values.Get("scope") != DEFAULT_OIDC_SCOPES {
				t.Fatalf("expected scope %q, got %q", DEFAULT_OIDC_SCOPES, values.Get("scope"))
			}
			return jsonResponse(http.StatusOK, `{"access_token":"fresh-token"}`), nil
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
			return nil, nil
		}
	})
	defer restore()

	originalIssuer := DEFAULT_OIDC_ISSUER
	DEFAULT_OIDC_ISSUER = "stub://issuer.example"
	t.Cleanup(func() {
		DEFAULT_OIDC_ISSUER = originalIssuer
	})

	debug := false
	got, err := GetPasswordGrantAccessToken("dex-user", "secret", &debug)
	if err != nil {
		t.Fatalf("GetPasswordGrantAccessToken returned error: %v", err)
	}
	if got != "fresh-token" {
		t.Fatalf("expected access token, got %q", got)
	}

	cachedToken, err := os.ReadFile(getAccessTokenCachePath())
	if err != nil {
		t.Fatalf("failed to read cached access token: %v", err)
	}
	if string(cachedToken) != "fresh-token" {
		t.Fatalf("expected cached access token, got %q", string(cachedToken))
	}
}

func TestGetUserNameFromAccessToken(t *testing.T) {
	token := makeTestJWT(t, map[string]any{
		"exp":   9999999999,
		"name":  "alice",
		"email": "alice@example.com",
	})

	got, err := GetUserNameFromAccessToken(token, "email")
	if err != nil {
		t.Fatalf("GetUserNameFromAccessToken returned error: %v", err)
	}
	if got != "alice@example.com" {
		t.Fatalf("expected email claim, got %q", got)
	}

	got, err = GetUserNameFromAccessToken(token, "")
	if err != nil {
		t.Fatalf("GetUserNameFromAccessToken returned error for default claim: %v", err)
	}
	if got != "alice" {
		t.Fatalf("expected default name claim, got %q", got)
	}
}

func TestGetExternalIDFromAccessToken(t *testing.T) {
	token := makeTestJWT(t, map[string]any{
		"exp":   9999999999,
		"name":  "alice",
		"email": "alice@example.com",
	})

	got, err := GetExternalIDFromAccessToken(token, "email")
	if err != nil {
		t.Fatalf("GetExternalIDFromAccessToken returned error: %v", err)
	}
	if got != "alice@example.com" {
		t.Fatalf("expected email claim, got %q", got)
	}

	got, err = GetExternalIDFromAccessToken(token, "")
	if err != nil {
		t.Fatalf("GetExternalIDFromAccessToken returned error for default claim: %v", err)
	}
	if got != "alice" {
		t.Fatalf("expected default name claim, got %q", got)
	}
}

func TestGetUserNameFromAccessTokenRejectsMissingClaim(t *testing.T) {
	token := makeTestJWT(t, map[string]any{
		"exp":  9999999999,
		"name": "alice",
	})

	if _, err := GetUserNameFromAccessToken(token, "email"); err == nil {
		t.Fatal("expected missing claim to return an error")
	}
}

func TestBuildAuthCodeURLRejectsEmptyState(t *testing.T) {
	conf := buildOAuthConfig("https://issuer.example/auth", "https://issuer.example/token")

	if _, err := buildAuthCodeURL(conf, "form_post"); err == nil {
		t.Fatal("expected empty oauth state to return an error")
	}
}

func TestParseAccessTokenResponseRejectsInvalidJSON(t *testing.T) {
	if _, err := parseAccessTokenResponse(strings.NewReader("{")); err == nil {
		t.Fatal("expected invalid JSON to return an error")
	}
}

func stubDefaultTransport(t *testing.T, roundTrip func(*http.Request) (*http.Response, error)) func() {
	t.Helper()

	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.RegisterProtocol("stub", roundTripFunc(roundTrip))
	http.DefaultTransport = transport
	return func() {
		http.DefaultTransport = original
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{URL: &url.URL{Scheme: "stub", Host: "issuer.example"}},
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
}
