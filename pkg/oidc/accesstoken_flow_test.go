package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestParseManualAuthCodeRejectsURLInput(t *testing.T) {
	for _, input := range []string{
		"http://127.0.0.1:5556/dex/auth/local/login?back=&state=jwt75qxgvdinqnmgd2y7j4hch",
		"urn:ietf:wg:oauth:2.0:oob?code=test-code&state=test-state",
	} {
		_, err := parseManualAuthCode(input)
		if err == nil {
			t.Fatalf("expected URL input %q to return an error", input)
		}
		if !strings.Contains(err.Error(), "paste only the authorization code") {
			t.Fatalf("expected authorization code guidance, got %v", err)
		}
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

func TestGetAuthCodeResultManualFlowRejectsURLInput(t *testing.T) {
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
		t.Fatal("expected URL input to be rejected")
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
	waitForCodeServerFunc = func(listener net.Listener, closeWindowDelay int) (authCodeResult, error) {
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
			var resolvedPort int
			reservePortFunc = func(basePort int) (net.Listener, int, error) {
				if basePort != 8080 {
					t.Fatalf("expected base port 8080, got %d", basePort)
				}
				listener, port := reserveTestPort(t)
				resolvedPort = port
				return listener, port, nil
			}
			openBrowserFunc = func(authCodeURL string) error {
				openBrowserCalled = true
				parsedURL, err := url.Parse(authCodeURL)
				if err != nil {
					t.Fatalf("failed to parse auth url: %v", err)
				}
				if got := parsedURL.Query().Get("redirect_uri"); got != fmt.Sprintf("http://127.0.0.1:%d", resolvedPort) {
					t.Fatalf("expected redirect_uri to use resolved port %d, got %q", resolvedPort, got)
				}
				return nil
			}
			closeBrowserTabFunc = func(urlPrefix string, delaySecs int) {
				t.Fatal("expected no tab close when the close window delay is disabled")
			}
			waitForCodeServerFunc = func(listener net.Listener, closeWindowDelay int) (authCodeResult, error) {
				if closeWindowDelay != 0 {
					t.Fatalf("expected close window delay 0, got %d", closeWindowDelay)
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
		reservePortFunc = func(basePort int) (net.Listener, int, error) {
			listener, port := reserveTestPort(t)
			return listener, port, nil
		}
		waitForCodeServerFunc = func(listener net.Listener, closeWindowDelay int) (authCodeResult, error) {
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
		reservePortFunc = func(basePort int) (net.Listener, int, error) {
			listener, port := reserveTestPort(t)
			return listener, port, nil
		}
		waitForCodeServerFunc = func(listener net.Listener, closeWindowDelay int) (authCodeResult, error) {
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
		waitForCodeServerFunc = func(listener net.Listener, closeWindowDelay int) (authCodeResult, error) {
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

func TestListenAddressBasePort(t *testing.T) {
	tests := []struct {
		name          string
		listenAddress string
		want          int
		wantErr       bool
	}{
		{name: "default port only", listenAddress: ":8080", want: 8080},
		{name: "host and port", listenAddress: "127.0.0.1:9000", want: 9000},
		{name: "empty", listenAddress: "", wantErr: true},
		{name: "missing port", listenAddress: "127.0.0.1", wantErr: true},
		{name: "non numeric port", listenAddress: ":abc", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := listenAddressBasePort(tc.listenAddress)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("listenAddressBasePort returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected port %d, got %d", tc.want, got)
			}
		})
	}
}

func TestReserveCallbackListenerReturnsBasePortWhenFree(t *testing.T) {
	listener, port := reserveTestPort(t)
	listener.Close()

	reserved, reservedPort, err := reserveCallbackListener(port)
	if err != nil {
		t.Fatalf("reserveCallbackListener returned error: %v", err)
	}
	defer reserved.Close()

	if reservedPort != port {
		t.Fatalf("expected base port %d to be reused, got %d", port, reservedPort)
	}
}

func TestReserveCallbackListenerShiftsPortWhenOccupied(t *testing.T) {
	listener, port := reserveTestPort(t)
	defer listener.Close()

	reserved, reservedPort, err := reserveCallbackListener(port)
	if err != nil {
		t.Fatalf("reserveCallbackListener returned error: %v", err)
	}
	defer reserved.Close()

	if reservedPort <= port {
		t.Fatalf("expected a shifted port above %d, got %d", port, reservedPort)
	}
}

func TestReserveCallbackListenerExhaustsAttempts(t *testing.T) {
	savedAttempts := maxPortSearchAttempts
	maxPortSearchAttempts = 2
	defer func() { maxPortSearchAttempts = savedAttempts }()

	listener, port := reserveTestPort(t)
	defer listener.Close()

	blocker, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+1))
	if err != nil {
		t.Fatalf("failed to bind blocker port: %v", err)
	}
	defer blocker.Close()

	if _, _, err := reserveCallbackListener(port); err == nil {
		t.Fatal("expected reservation to fail once all candidate ports are occupied")
	}
}

func TestWaitForCodeServerServesStaticClosePage(t *testing.T) {
	listener, port := reserveTestPort(t)
	defer listener.Close()

	resultCh := make(chan authCodeResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := waitForCodeServer(listener, 0)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	waitForServerReady(t, port)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/?code=test-code&state=test-state", port))
	if err != nil {
		t.Fatalf("failed to call callback: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read callback response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("expected text/html content type, got %q", resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(body), "You may close this window now.") {
		t.Fatal("expected the static close message when auto-close is disabled")
	}
	if strings.Contains(string(body), "window.close()") {
		t.Fatal("expected no auto-close script when auto-close is disabled")
	}

	select {
	case result := <-resultCh:
		if result.Code != "test-code" {
			t.Fatalf("expected auth code, got %q", result.Code)
		}
	case err := <-errCh:
		t.Fatalf("waitForCodeServer returned error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for waitForCodeServer result")
	}
}

func TestWaitForCodeServerServesAutoClosePage(t *testing.T) {
	listener, port := reserveTestPort(t)
	defer listener.Close()

	resultCh := make(chan authCodeResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := waitForCodeServer(listener, 7)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	waitForServerReady(t, port)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/?code=test-code&state=test-state", port))
	if err != nil {
		t.Fatalf("failed to call callback: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read callback response: %v", err)
	}

	if !strings.Contains(string(body), "This window will close in 7 seconds.") {
		t.Fatal("expected the countdown message when an auto-close delay is set")
	}
	if !strings.Contains(string(body), "var secs = 7;") {
		t.Fatal("expected the configured delay to be embedded in the auto-close script")
	}
	if !strings.Contains(string(body), "el.textContent = 'You may close this window now.';") {
		t.Fatal("expected the auto-close script to fall back to the static message before closing")
	}
	if strings.Contains(string(body), "__CLOSE_MSG__") || strings.Contains(string(body), "__CLOSE_SCRIPT__") {
		t.Fatal("expected all template placeholders to be replaced")
	}

	select {
	case result := <-resultCh:
		if result.Code != "test-code" {
			t.Fatalf("expected auth code, got %q", result.Code)
		}
	case err := <-errCh:
		t.Fatalf("waitForCodeServer returned error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for waitForCodeServer result")
	}
}

func TestCloseBrowserTabNoopOnNonDarwin(t *testing.T) {
	restore := saveOIDCFlowGlobals()
	defer restore()

	currentGOOS = "linux"
	osascriptStartFunc = func(script string) error {
		t.Fatal("expected no osascript invocation on non-darwin platforms")
		return nil
	}

	closeBrowserTab("http://127.0.0.1:8080", 7)
}

func TestCloseBrowserTabBuildsScriptOnDarwin(t *testing.T) {
	restore := saveOIDCFlowGlobals()
	defer restore()

	currentGOOS = "darwin"
	var capturedScript string
	osascriptStartFunc = func(script string) error {
		capturedScript = script
		return nil
	}

	closeBrowserTab("http://127.0.0.1:8080", 7)

	if !strings.Contains(capturedScript, "delay 7.5") {
		t.Fatalf("expected the script to wait out the page countdown, got %q", capturedScript)
	}
	if !strings.Contains(capturedScript, "http://127.0.0.1:8080") {
		t.Fatalf("expected the script to match the callback URL prefix, got %q", capturedScript)
	}
	if !strings.Contains(capturedScript, "Google Chrome") || !strings.Contains(capturedScript, "Safari") {
		t.Fatalf("expected the script to cover Chrome and Safari, got %q", capturedScript)
	}
}

func TestGetAuthCodeResultAutomaticFlowFiresTabClose(t *testing.T) {
	restore := saveOIDCFlowGlobals()
	defer restore()

	currentGOOS = "darwin"
	DEFAULT_OIDC_CLOSE_WINDOW_DELAY = "7"

	var resolvedPort int
	reservePortFunc = func(basePort int) (net.Listener, int, error) {
		listener, port := reserveTestPort(t)
		resolvedPort = port
		return listener, port, nil
	}
	openBrowserFunc = func(authCodeURL string) error { return nil }
	closeCalls := make(chan string, 1)
	closeBrowserTabFunc = func(urlPrefix string, delaySecs int) {
		closeCalls <- fmt.Sprintf("%s|%d", urlPrefix, delaySecs)
	}
	waitForCodeServerFunc = func(listener net.Listener, closeWindowDelay int) (authCodeResult, error) {
		if closeWindowDelay != 7 {
			t.Fatalf("expected close window delay 7, got %d", closeWindowDelay)
		}
		return authCodeResult{Code: "test-code", State: "test-state", AttestationData: "code=test-code&state=test-state"}, nil
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
		t.Fatalf("getAuthCodeResult returned error: %v", err)
	}
	if result.Code != "test-code" {
		t.Fatalf("expected code to be returned, got %q", result.Code)
	}

	select {
	case call := <-closeCalls:
		want := fmt.Sprintf("http://127.0.0.1:%d|7", resolvedPort)
		if call != want {
			t.Fatalf("expected tab close call %q, got %q", want, call)
		}
	default:
		t.Fatal("expected the tab close to fire when an auto-close delay is set")
	}
}

func TestCloseWindowHTML(t *testing.T) {
	page := closeWindowHTML(0)
	if !strings.Contains(page, "Authentication successful") {
		t.Error("closeWindowHTML should contain the success message")
	}
	if !strings.Contains(page, "You may close this window now.") {
		t.Error("closeWindowHTML should contain the static close instruction")
	}
	if strings.Contains(page, "window.close()") {
		t.Error("closeWindowHTML with no delay should not contain the auto-close script")
	}
}

func TestCloseWindowHTMLAutoClose(t *testing.T) {
	page := closeWindowHTML(5)
	if !strings.Contains(page, "This window will close in 5 seconds.") {
		t.Error("closeWindowHTML with a delay should contain the countdown message")
	}
	if !strings.Contains(page, "var secs = 5;") {
		t.Error("closeWindowHTML should embed the configured delay in the script")
	}
	if !strings.Contains(page, "el.textContent = 'You may close this window now.';") {
		t.Error("closeWindowHTML script should fall back to the static close message before attempting window.close()")
	}
	if strings.Contains(page, "__CLOSE_MSG__") || strings.Contains(page, "__CLOSE_SCRIPT__") {
		t.Error("closeWindowHTML should replace all template placeholders")
	}
}

func waitForServerReady(t *testing.T, port int) {
	t.Helper()
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server on port %d did not start in time", port)
}

func saveOIDCFlowGlobals() func() {
	savedGOOS := currentGOOS
	savedInput := authCodeInputReader
	savedOpenBrowser := openBrowserFunc
	savedWaitForCodeServer := waitForCodeServerFunc
	savedCloseBrowserTab := closeBrowserTabFunc
	savedReservePort := reservePortFunc
	savedOsaScriptStart := osascriptStartFunc
	savedCloseWindowDelay := DEFAULT_OIDC_CLOSE_WINDOW_DELAY
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
		closeBrowserTabFunc = savedCloseBrowserTab
		reservePortFunc = savedReservePort
		osascriptStartFunc = savedOsaScriptStart
		DEFAULT_OIDC_CLOSE_WINDOW_DELAY = savedCloseWindowDelay
		oidcDiscoveryFunc = savedDiscovery
		buildPKCEOAuthConfigFunc = savedBuildPKCE
		getAuthCodeResultFunc = savedGetAuthCodeResult
		exchangeAuthCodeFunc = savedExchange
		randomReadFunc = savedRandomRead
	}
}

// reserveTestPort binds a listener on an OS-assigned free port and returns it
// together with the port number. The caller is responsible for closing it.
func reserveTestPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve test port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return listener, port
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read failure")
}
