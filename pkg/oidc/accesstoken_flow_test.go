package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratePKCEParametersProducesVerifierAndChallenge(t *testing.T) {
	verifier, challenge, err := generatePKCEParameters()
	if err != nil {
		t.Fatalf("generatePKCEParameters returned error: %v", err)
	}
	if verifier == "" {
		t.Fatal("expected PKCE verifier to be populated")
	}
	if challenge == "" {
		t.Fatal("expected PKCE challenge to be populated")
	}

	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("expected challenge %q, got %q", want, challenge)
	}
}

func TestGenerateOAuthStateProducesBase64Value(t *testing.T) {
	state, err := generateOAuthState()
	if err != nil {
		t.Fatalf("generateOAuthState returned error: %v", err)
	}
	if state == "" {
		t.Fatal("expected oauth state to be populated")
	}
	if _, err := base64.RawURLEncoding.DecodeString(state); err != nil {
		t.Fatalf("expected oauth state to be URL-safe base64, got %v", err)
	}
}

func TestPKCEAndStateGenerationErrors(t *testing.T) {
	restore := saveOIDCFlowGlobals()
	defer restore()

	randomReadFunc = func([]byte) (int, error) {
		return 0, errors.New("read failure")
	}

	if _, _, err := generatePKCEParameters(); err == nil {
		t.Fatal("expected generatePKCEParameters to return an error when randomness fails")
	}
	if _, err := generateOAuthState(); err == nil {
		t.Fatal("expected generateOAuthState to return an error when randomness fails")
	}
	if _, err := buildPKCEOAuthConfig("https://issuer.example/auth", "https://issuer.example/token"); err == nil {
		t.Fatal("expected buildPKCEOAuthConfig to return an error when randomness fails")
	}
}

func TestGetOIDCDiscoveryRejectsHTTPError(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusInternalServerError, `{"error":"unavailable"}`), nil
	})
	defer restore()

	originalIssuer := DEFAULT_OIDC_ISSUER
	DEFAULT_OIDC_ISSUER = "stub://issuer.example"
	t.Cleanup(func() {
		DEFAULT_OIDC_ISSUER = originalIssuer
	})

	debug := false
	if _, _, err := GetOIDCDiscovery(&debug); err == nil {
		t.Fatal("expected HTTP discovery failure to return an error")
	}
}

func TestGetOIDCDiscoveryRejectsInvalidJSON(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{`), nil
	})
	defer restore()

	originalIssuer := DEFAULT_OIDC_ISSUER
	DEFAULT_OIDC_ISSUER = "stub://issuer.example"
	t.Cleanup(func() {
		DEFAULT_OIDC_ISSUER = originalIssuer
	})

	debug := false
	if _, _, err := GetOIDCDiscovery(&debug); err == nil {
		t.Fatal("expected invalid discovery JSON to return an error")
	}
}

func TestExchangeAuthCodeRejectsHTTPError(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, `{"error":"invalid_grant"}`), nil
	})
	defer restore()

	conf := &oauthConfig{
		ClientID:    "client-id",
		RedirectURL: "http://127.0.0.1:8080",
		TokenURL:    "stub://issuer.example/token",
	}

	if _, err := exchangeAuthCode(conf, "bad-code"); err == nil {
		t.Fatal("expected exchangeAuthCode to return an error")
	}
}

func TestExchangeAuthCodeAdditionalErrorPaths(t *testing.T) {
	t.Run("invalid token url", func(t *testing.T) {
		conf := &oauthConfig{TokenURL: "://bad-url"}
		if _, err := exchangeAuthCode(conf, "code"); err == nil {
			t.Fatal("expected invalid token URL to return an error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return nil, io.EOF
		})
		defer restore()

		conf := &oauthConfig{TokenURL: "stub://issuer.example/token"}
		if _, err := exchangeAuthCode(conf, "code"); err == nil {
			t.Fatal("expected transport error to return an error")
		}
	})

	t.Run("invalid response json", func(t *testing.T) {
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{`), nil
		})
		defer restore()

		conf := &oauthConfig{TokenURL: "stub://issuer.example/token"}
		if _, err := exchangeAuthCode(conf, "code"); err == nil {
			t.Fatal("expected invalid token response JSON to return an error")
		}
	})

	t.Run("cache write error", func(t *testing.T) {
		filePath := filepath.Join(t.TempDir(), "home-file")
		if err := os.WriteFile(filePath, []byte("not-a-dir"), 0600); err != nil {
			t.Fatalf("failed to create fake home file: %v", err)
		}
		t.Setenv("HOME", filePath)

		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"access_token":"fresh-token"}`), nil
		})
		defer restore()

		conf := &oauthConfig{TokenURL: "stub://issuer.example/token"}
		if _, err := exchangeAuthCode(conf, "code"); err == nil {
			t.Fatal("expected cache path creation to return an error")
		}
	})
}

func TestParseManualAuthCodeRejectsEmptyValue(t *testing.T) {
	if _, err := parseManualAuthCode(" \n "); err == nil {
		t.Fatal("expected empty authorization input to return an error")
	}
}

func TestParseManualAuthCodeHandlesRawCode(t *testing.T) {
	result, err := parseManualAuthCode("raw-authorization-code")
	if err != nil {
		t.Fatalf("parseManualAuthCode returned error: %v", err)
	}
	if result.Code != "raw-authorization-code" {
		t.Fatalf("expected raw code to be preserved, got %q", result.Code)
	}
	if result.AttestationData != "code=raw-authorization-code" {
		t.Fatalf("expected attestation data to contain the code, got %q", result.AttestationData)
	}
}

func TestParseManualAuthCodeRejectsBrowserURL(t *testing.T) {
	_, err := parseManualAuthCode("http://127.0.0.1:5556/dex/auth/local/login?back=&state=jwt75qxgvdinqnmgd2y7j4hch")
	if err == nil {
		t.Fatal("expected browser URL input to return an error")
	}
	if !strings.Contains(err.Error(), "paste only the authorization code") {
		t.Fatalf("expected authorization code guidance, got %v", err)
	}
}

func TestBuildAuthAttestationDataAndAccessTokenPropagatesExchangeError(t *testing.T) {
	conf := &oauthConfig{CodeVerifier: "test-verifier"}
	authResult := authCodeResult{
		Code:            "test-code",
		AttestationData: "code=test-code&state=test-state",
	}

	_, _, err := buildAuthAttestationDataAndAccessToken(conf, authResult, "", func(*oauthConfig, string) (string, error) {
		return "", io.EOF
	})
	if err == nil {
		t.Fatal("expected exchange error to be returned")
	}
}

func TestGetAuthAttestationDataReturnsDiscoveryError(t *testing.T) {
	originalIssuer := DEFAULT_OIDC_ISSUER
	DEFAULT_OIDC_ISSUER = "://invalid-issuer"
	t.Cleanup(func() {
		DEFAULT_OIDC_ISSUER = originalIssuer
	})

	responseMode := "form_post"
	debug := false
	if _, err := GetAuthAttestationData(&responseMode, &debug); err == nil {
		t.Fatal("expected GetAuthAttestationData to return discovery error")
	}
}

func TestGetAuthAttestationDataAndAccessTokenReturnsDiscoveryError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	originalIssuer := DEFAULT_OIDC_ISSUER
	DEFAULT_OIDC_ISSUER = "://invalid-issuer"
	t.Cleanup(func() {
		DEFAULT_OIDC_ISSUER = originalIssuer
	})

	responseMode := "form_post"
	debug := false
	if _, _, err := GetAuthAttestationDataAndAccessToken(&responseMode, &debug); err == nil {
		t.Fatal("expected GetAuthAttestationDataAndAccessToken to return discovery error")
	}
}

func TestGetAuthAccessTokenReturnsDiscoveryErrorWhenCacheMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	originalIssuer := DEFAULT_OIDC_ISSUER
	DEFAULT_OIDC_ISSUER = "://invalid-issuer"
	t.Cleanup(func() {
		DEFAULT_OIDC_ISSUER = originalIssuer
	})

	responseMode := "form_post"
	debug := false
	if _, err := GetAuthAccessToken(&responseMode, &debug); err == nil {
		t.Fatal("expected GetAuthAccessToken to return discovery error")
	}
}

func TestBuildAuthCodeURLOmitsEmptyResponseMode(t *testing.T) {
	conf := buildOAuthConfig("https://issuer.example/auth", "https://issuer.example/token")
	conf.State = "test-state"
	conf.ResponseType = ""

	authURL, err := buildAuthCodeURL(conf, "")
	if err != nil {
		t.Fatalf("buildAuthCodeURL returned error: %v", err)
	}

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse auth url: %v", err)
	}
	values := parsedURL.Query()
	if got := values.Get("response_type"); got != "code" {
		t.Fatalf("expected default response_type, got %q", got)
	}
	if got := values.Get("response_mode"); got != "" {
		t.Fatalf("expected response_mode to be omitted, got %q", got)
	}
	if !strings.Contains(values.Get("scope"), "openid") {
		t.Fatalf("expected default scopes to be present, got %q", values.Get("scope"))
	}
}

func TestGetAuthCodeResultManualFlowRejectsBrowserURL(t *testing.T) {
	restore := saveOIDCFlowGlobals()
	defer restore()

	currentGOOS = "linux"
	authCodeInputReader = strings.NewReader("http://127.0.0.1:5556/dex/auth/local/login?back=&code=test-code&state=dex-state\n")

	conf := &oauthConfig{
		AuthURL:      "https://issuer.example/auth",
		RedirectURL:  "http://127.0.0.1:8080",
		ClientID:     "client-id",
		State:        "test-state",
		ResponseType: "code",
		Scopes:       []string{"openid"},
	}
	responseMode := "query"

	_, err := getAuthCodeResult(conf, &responseMode)
	if err == nil {
		t.Fatal("expected browser URL input to be rejected")
	}
	if !strings.Contains(err.Error(), "paste only the authorization code") {
		t.Fatalf("expected authorization code guidance, got %v", err)
	}
}

func TestGetAuthCodeResultManualFlowAcceptsBareCode(t *testing.T) {
	restore := saveOIDCFlowGlobals()
	defer restore()

	currentGOOS = "other" // Force manual flow
	authCodeInputReader = strings.NewReader("test-code\n")

	conf := &oauthConfig{
		AuthURL:      "https://issuer.example/auth",
		RedirectURL:  "http://127.0.0.1:8080",
		ClientID:     "client-id",
		State:        "test-state",
		ResponseType: "code",
		Scopes:       []string{"openid"},
	}
	responseMode := "query"

	result, err := getAuthCodeResult(conf, &responseMode)
	if err != nil {
		t.Fatalf("expected getAuthCodeResult to accept bare code, got error: %v", err)
	}
	if result.Code != "test-code" {
		t.Fatalf("expected code to be parsed, got %q", result.Code)
	}
}

func TestGetAuthCodeResultManualFlowPropagatesReadError(t *testing.T) {
	restore := saveOIDCFlowGlobals()
	defer restore()

	currentGOOS = "other" // Force manual flow
	authCodeInputReader = errReader{}

	conf := &oauthConfig{
		AuthURL:      "https://issuer.example/auth",
		RedirectURL:  "http://127.0.0.1:8080",
		ClientID:     "client-id",
		State:        "test-state",
		ResponseType: "code",
		Scopes:       []string{"openid"},
	}
	responseMode := "query"

	if _, err := getAuthCodeResult(conf, &responseMode); err == nil {
		t.Fatal("expected getAuthCodeResult to return scanner read error")
	}
}

func TestGetAuthCodeResultManualFlowHandlesEOFWithoutInput(t *testing.T) {
	restore := saveOIDCFlowGlobals()
	defer restore()

	currentGOOS = "other" // Force manual flow
	authCodeInputReader = strings.NewReader("")

	conf := &oauthConfig{
		AuthURL:      "https://issuer.example/auth",
		RedirectURL:  "http://127.0.0.1:8080",
		ClientID:     "client-id",
		State:        "test-state",
		ResponseType: "code",
		Scopes:       []string{"openid"},
	}
	responseMode := "query"

	if _, err := getAuthCodeResult(conf, &responseMode); err == nil {
		t.Fatal("expected missing manual input to return an error")
	}
}

func TestGetAuthCodeResultLinuxUsesManualFlow(t *testing.T) {
	restore := saveOIDCFlowGlobals()
	defer restore()

	currentGOOS = "linux"
	authCodeInputReader = strings.NewReader("test-code\n")
	automaticFlowCalled := false
	openBrowserFunc = func(authCodeURL string) error {
		automaticFlowCalled = true
		return nil
	}
	waitForCodeServerFunc = func(listenAddress string) (authCodeResult, error) {
		automaticFlowCalled = true
		return authCodeResult{}, fmt.Errorf("automatic callback flow should not be used on linux")
	}

	conf := &oauthConfig{
		AuthURL:      "https://issuer.example/auth",
		RedirectURL:  "http://127.0.0.1:8080",
		ClientID:     "client-id",
		State:        "test-state",
		ResponseType: "code",
		Scopes:       []string{"openid"},
	}
	responseMode := "query"

	result, err := getAuthCodeResult(conf, &responseMode)
	if err != nil {
		t.Fatalf("expected linux to use manual auth code flow, got error: %v", err)
	}
	if automaticFlowCalled {
		t.Fatal("expected linux to avoid automatic callback flow")
	}
	if result.Code != "test-code" {
		t.Fatalf("expected manual code to be parsed, got %q", result.Code)
	}
	if conf.RedirectURL != oidcOutOfBandRedirectURL {
		t.Fatalf("expected linux manual flow to use redirect %q, got %q", oidcOutOfBandRedirectURL, conf.RedirectURL)
	}
}

func TestGetAuthCodeResultAutomaticFlow(t *testing.T) {
	tests := []struct {
		os string
	}{
		{"darwin"},
		{"windows"},
	}

	for _, tc := range tests {
		t.Run(tc.os, func(t *testing.T) {
			restore := saveOIDCFlowGlobals()
			defer restore()

			currentGOOS = tc.os
			openBrowserCalled := false
			openBrowserFunc = func(authCodeURL string) error {
				openBrowserCalled = true
				return nil
			}
			waitForCodeServerFunc = func(listenAddress string) (authCodeResult, error) {
				if listenAddress != DEFAULT_OIDC_LISTEN_ADDRESS {
					t.Fatalf("expected listen address %q, got %q", DEFAULT_OIDC_LISTEN_ADDRESS, listenAddress)
				}
				return authCodeResult{Code: "test-code", State: "test-state", AttestationData: "code=test-code&state=test-state"}, nil
			}

			conf := &oauthConfig{
				AuthURL:       "https://issuer.example/auth",
				RedirectURL:   "http://127.0.0.1:8080",
				ClientID:      "client-id",
				State:         "test-state",
				ResponseType:  "code",
				Scopes:        []string{"openid"},
				CodeChallenge: "challenge",
			}
			responseMode := "query"

			result, err := getAuthCodeResult(conf, &responseMode)
			if err != nil {
				t.Fatalf("getAuthCodeResult returned error: %v", err)
			}
			if !openBrowserCalled {
				t.Fatal("expected automatic flow to invoke browser opener")
			}
			if result.Code != "test-code" {
				t.Fatalf("expected code to be returned, got %q", result.Code)
			}
		})
	}
}

func TestGetAuthCodeResultAutomaticFlowErrors(t *testing.T) {
	t.Run("callback server error", func(t *testing.T) {
		restore := saveOIDCFlowGlobals()
		defer restore()

		currentGOOS = "darwin"
		openBrowserFunc = func(authCodeURL string) error { return nil }
		waitForCodeServerFunc = func(listenAddress string) (authCodeResult, error) {
			return authCodeResult{}, io.EOF
		}

		conf := &oauthConfig{
			AuthURL:      "https://issuer.example/auth",
			RedirectURL:  "http://127.0.0.1:8080",
			ClientID:     "client-id",
			State:        "test-state",
			ResponseType: "code",
			Scopes:       []string{"openid"},
		}
		responseMode := "query"

		if _, err := getAuthCodeResult(conf, &responseMode); err == nil {
			t.Fatal("expected server error to be returned")
		}
	})

	t.Run("missing callback code", func(t *testing.T) {
		restore := saveOIDCFlowGlobals()
		defer restore()

		currentGOOS = "darwin"
		openBrowserFunc = func(authCodeURL string) error { return nil }
		waitForCodeServerFunc = func(listenAddress string) (authCodeResult, error) {
			return authCodeResult{State: "test-state"}, nil
		}

		conf := &oauthConfig{
			AuthURL:      "https://issuer.example/auth",
			RedirectURL:  "http://127.0.0.1:8080",
			ClientID:     "client-id",
			State:        "test-state",
			ResponseType: "code",
			Scopes:       []string{"openid"},
		}
		responseMode := "query"

		if _, err := getAuthCodeResult(conf, &responseMode); err == nil {
			t.Fatal("expected missing callback code to return an error")
		}
	})
}

func TestStartOIDCAuthCodeFlowSuccess(t *testing.T) {
	restore := saveOIDCFlowGlobals()
	defer restore()

	oidcDiscoveryFunc = func(debug *bool) (string, string, error) {
		return "https://issuer.example/auth", "https://issuer.example/token", nil
	}
	buildPKCEOAuthConfigFunc = func(authURL, tokenURL string) (*oauthConfig, error) {
		return &oauthConfig{AuthURL: authURL, TokenURL: tokenURL, CodeVerifier: "verifier"}, nil
	}
	getAuthCodeResultFunc = func(conf *oauthConfig, responseMode *string) (authCodeResult, error) {
		return authCodeResult{Code: "test-code", State: conf.State, AttestationData: "code=test-code"}, nil
	}

	responseMode := "query"
	debug := false
	conf, result, err := startOIDCAuthCodeFlow(&responseMode, &debug)
	if err != nil {
		t.Fatalf("startOIDCAuthCodeFlow returned error: %v", err)
	}
	if conf.TokenURL != "https://issuer.example/token" {
		t.Fatalf("expected token url to be preserved, got %q", conf.TokenURL)
	}
	if result.Code != "test-code" {
		t.Fatalf("expected auth result to be returned, got %q", result.Code)
	}
}

func TestStartOIDCAuthCodeFlowErrors(t *testing.T) {
	t.Run("pkce config error", func(t *testing.T) {
		restore := saveOIDCFlowGlobals()
		defer restore()

		oidcDiscoveryFunc = func(debug *bool) (string, string, error) {
			return "https://issuer.example/auth", "https://issuer.example/token", nil
		}
		buildPKCEOAuthConfigFunc = func(authURL, tokenURL string) (*oauthConfig, error) {
			return nil, io.EOF
		}

		responseMode := "query"
		debug := false
		if _, _, err := startOIDCAuthCodeFlow(&responseMode, &debug); err == nil {
			t.Fatal("expected PKCE config error")
		}
	})

	t.Run("auth code result error", func(t *testing.T) {
		restore := saveOIDCFlowGlobals()
		defer restore()

		oidcDiscoveryFunc = func(debug *bool) (string, string, error) {
			return "https://issuer.example/auth", "https://issuer.example/token", nil
		}
		buildPKCEOAuthConfigFunc = func(authURL, tokenURL string) (*oauthConfig, error) {
			return &oauthConfig{AuthURL: authURL, TokenURL: tokenURL}, nil
		}
		getAuthCodeResultFunc = func(conf *oauthConfig, responseMode *string) (authCodeResult, error) {
			return authCodeResult{}, io.EOF
		}

		responseMode := "query"
		debug := false
		if _, _, err := startOIDCAuthCodeFlow(&responseMode, &debug); err == nil {
			t.Fatal("expected auth code result error")
		}
	})
}

func TestOIDCWrapperSuccessPaths(t *testing.T) {
	t.Run("GetAuthAttestationData", func(t *testing.T) {
		restore := saveOIDCFlowGlobals()
		defer restore()

		oidcDiscoveryFunc = func(debug *bool) (string, string, error) {
			return "https://issuer.example/auth", "https://issuer.example/token", nil
		}
		buildPKCEOAuthConfigFunc = func(authURL, tokenURL string) (*oauthConfig, error) {
			return &oauthConfig{AuthURL: authURL, TokenURL: tokenURL, CodeVerifier: "verifier"}, nil
		}
		getAuthCodeResultFunc = func(conf *oauthConfig, responseMode *string) (authCodeResult, error) {
			return authCodeResult{Code: "test-code", AttestationData: "code=test-code"}, nil
		}

		responseMode := "query"
		debug := false
		got, err := GetAuthAttestationData(&responseMode, &debug)
		if err != nil {
			t.Fatalf("GetAuthAttestationData returned error: %v", err)
		}
		if !strings.Contains(got, "code_verifier=verifier") {
			t.Fatalf("expected code verifier in attestation data, got %q", got)
		}
	})

	t.Run("GetAuthAttestationDataAndAccessToken", func(t *testing.T) {
		restore := saveOIDCFlowGlobals()
		defer restore()
		t.Setenv("HOME", t.TempDir())

		oidcDiscoveryFunc = func(debug *bool) (string, string, error) {
			return "https://issuer.example/auth", "https://issuer.example/token", nil
		}
		buildPKCEOAuthConfigFunc = func(authURL, tokenURL string) (*oauthConfig, error) {
			return &oauthConfig{AuthURL: authURL, TokenURL: tokenURL, CodeVerifier: "verifier"}, nil
		}
		getAuthCodeResultFunc = func(conf *oauthConfig, responseMode *string) (authCodeResult, error) {
			return authCodeResult{Code: "test-code", AttestationData: "code=test-code"}, nil
		}
		exchangeAuthCodeFunc = func(conf *oauthConfig, code string) (string, error) {
			return "fresh-token", nil
		}

		responseMode := "query"
		debug := false
		attestationData, accessToken, err := GetAuthAttestationDataAndAccessToken(&responseMode, &debug)
		if err != nil {
			t.Fatalf("GetAuthAttestationDataAndAccessToken returned error: %v", err)
		}
		if accessToken != "fresh-token" || !strings.Contains(attestationData, "code_verifier=verifier") {
			t.Fatalf("unexpected wrapper result attestation=%q token=%q", attestationData, accessToken)
		}
	})

	t.Run("GetAuthAccessToken", func(t *testing.T) {
		restore := saveOIDCFlowGlobals()
		defer restore()
		t.Setenv("HOME", t.TempDir())

		oidcDiscoveryFunc = func(debug *bool) (string, string, error) {
			return "https://issuer.example/auth", "https://issuer.example/token", nil
		}
		buildPKCEOAuthConfigFunc = func(authURL, tokenURL string) (*oauthConfig, error) {
			return &oauthConfig{AuthURL: authURL, TokenURL: tokenURL}, nil
		}
		getAuthCodeResultFunc = func(conf *oauthConfig, responseMode *string) (authCodeResult, error) {
			return authCodeResult{Code: "test-code"}, nil
		}
		exchangeAuthCodeFunc = func(conf *oauthConfig, code string) (string, error) {
			return "fresh-token", nil
		}

		responseMode := "query"
		debug := false
		got, err := GetAuthAccessToken(&responseMode, &debug)
		if err != nil {
			t.Fatalf("GetAuthAccessToken returned error: %v", err)
		}
		if got != "fresh-token" {
			t.Fatalf("expected exchanged token, got %q", got)
		}
	})

	t.Run("GetAuthAccessToken manual flow exchanges with out-of-band redirect", func(t *testing.T) {
		restore := saveOIDCFlowGlobals()
		defer restore()
		t.Setenv("HOME", t.TempDir())

		currentGOOS = "linux"
		authCodeInputReader = strings.NewReader("test-code\n")
		openBrowserFunc = func(authCodeURL string) error {
			t.Fatal("linux should not open browser for automatic callback flow")
			return nil
		}
		waitForCodeServerFunc = func(listenAddress string) (authCodeResult, error) {
			t.Fatal("linux should not start automatic callback server")
			return authCodeResult{}, nil
		}
		oidcDiscoveryFunc = func(debug *bool) (string, string, error) {
			return "https://issuer.example/auth", "https://issuer.example/token", nil
		}
		exchangeAuthCodeFunc = func(conf *oauthConfig, code string) (string, error) {
			if code != "test-code" {
				t.Fatalf("expected auth code to be exchanged, got %q", code)
			}
			if conf.RedirectURL != oidcOutOfBandRedirectURL {
				t.Fatalf("expected redirect %q, got %q", oidcOutOfBandRedirectURL, conf.RedirectURL)
			}
			return "fresh-token", nil
		}

		responseMode := "query"
		debug := false
		got, err := GetAuthAccessToken(&responseMode, &debug)
		if err != nil {
			t.Fatalf("GetAuthAccessToken returned error: %v", err)
		}
		if got != "fresh-token" {
			t.Fatalf("expected exchanged token, got %q", got)
		}
	})
}

func TestAuthCodeResultFromRequest(t *testing.T) {
	t.Run("get request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/callback?code=test-code&state=test-state", nil)
		result, err := authCodeResultFromRequest(req)
		if err != nil {
			t.Fatalf("authCodeResultFromRequest returned error: %v", err)
		}
		if result.Code != "test-code" || result.State != "test-state" {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("post request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/callback", strings.NewReader("code=test-code&state=test-state"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		result, err := authCodeResultFromRequest(req)
		if err != nil {
			t.Fatalf("authCodeResultFromRequest returned error: %v", err)
		}
		if result.AttestationData != "code=test-code&state=test-state" {
			t.Fatalf("expected encoded post form, got %q", result.AttestationData)
		}
	})

	t.Run("missing code", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/callback?state=test-state", nil)
		if _, err := authCodeResultFromRequest(req); err == nil {
			t.Fatal("expected missing code to return an error")
		}
	})
}

func TestWaitForCodeServerRejectsInvalidListenAddress(t *testing.T) {
	if _, err := waitForCodeServer("bad address"); err == nil {
		t.Fatal("expected invalid listen address to return an error")
	}
}

func saveOIDCFlowGlobals() func() {
	savedGOOS := currentGOOS
	savedInput := authCodeInputReader
	savedOpenBrowser := openBrowserFunc
	savedWaitForCodeServer := waitForCodeServerFunc
	savedDiscovery := oidcDiscoveryFunc
	savedBuildPKCE := buildPKCEOAuthConfigFunc
	savedGetAuthCodeResult := getAuthCodeResultFunc
	savedExchange := exchangeAuthCodeFunc
	savedRandomRead := randomReadFunc

	return func() {
		currentGOOS = savedGOOS
		authCodeInputReader = savedInput
		openBrowserFunc = savedOpenBrowser
		waitForCodeServerFunc = savedWaitForCodeServer
		oidcDiscoveryFunc = savedDiscovery
		buildPKCEOAuthConfigFunc = savedBuildPKCE
		getAuthCodeResultFunc = savedGetAuthCodeResult
		exchangeAuthCodeFunc = savedExchange
		randomReadFunc = savedRandomRead
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read failure")
}
