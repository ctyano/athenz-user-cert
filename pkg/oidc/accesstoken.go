package oidc

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const oidcOutOfBandRedirectURL = "urn:ietf:wg:oauth:2.0:oob"

var (
	DEFAULT_OIDC_CLIENT_ID             = "athenz-user-cert"
	DEFAULT_OIDC_CLIENT_SECRET         = "athenz-user-cert"
	DEFAULT_OIDC_ISSUER                = "http://127.0.0.1:5556/dex"
	DEFAULT_OIDC_SCOPES                = "openid email profile"
	DEFAULT_OIDC_LISTEN_ADDRESS        = ":8080"
	DEFAULT_OIDC_ACCESS_TOKEN_PATH     = ".athenz/.accesstoken"
	DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM = "name"

	currentGOOS                   = runtime.GOOS
	authCodeInputReader io.Reader = os.Stdin
	openBrowserFunc               = func(authCodeURL string) error {
		switch currentGOOS {
		case "darwin":
			return exec.Command("open", authCodeURL).Start()
		case "linux":
			return exec.Command("xdg-open", authCodeURL).Start()
		case "windows":
			return exec.Command("rundll32", "url.dll,FileProtocolHandler", authCodeURL).Start()
		default:
			return nil
		}
	}
	waitForCodeServerFunc    = waitForCodeServer
	oidcDiscoveryFunc        = GetOIDCDiscovery
	buildPKCEOAuthConfigFunc = buildPKCEOAuthConfig
	getAuthCodeResultFunc    = getAuthCodeResult
	exchangeAuthCodeFunc     = exchangeAuthCode
	randomReadFunc           = rand.Read
)

func getAccessTokenCachePath() string {
	h, _ := os.UserHomeDir()
	return h + "/" + DEFAULT_OIDC_ACCESS_TOKEN_PATH
}

func getCachedAccessToken(debug bool) (string, error) {
	accessTokenFile := getAccessTokenCachePath()
	data, err := os.ReadFile(accessTokenFile)
	if err != nil {
		return "", fmt.Errorf("could not read the cache file, error: %v", err)
	}

	accessToken := strings.TrimSpace(string(data))
	if accessToken == "" {
		return "", fmt.Errorf("cached access token is empty")
	}

	expired, err := isAccessTokenExpired(accessToken, debug)
	if err != nil {
		return "", err
	}
	if expired {
		return "", fmt.Errorf("access token has expired")
	}

	return accessToken, nil
}

func isAccessTokenExpired(accessToken string, debug bool) (bool, error) {
	expiry, err := getJWTExpiry(accessToken)
	if err != nil {
		return false, fmt.Errorf("could not parse cached access token: %v", err)
	}

	if debug {
		fmt.Printf("Cached access token expires at %s\n", expiry.UTC().Format(time.RFC3339))
	}

	return !time.Now().Before(expiry), nil
}

func getJWTExpiry(rawJWT string) (time.Time, error) {
	claims, err := parseJWTClaims(rawJWT)
	if err != nil {
		return time.Time{}, err
	}

	expClaim, ok := claims["exp"]
	if !ok {
		return time.Time{}, fmt.Errorf("no exp claim in jwt")
	}

	expUnix, err := parseJWTNumericDate(expClaim)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid exp claim in jwt: %v", err)
	}

	return time.Unix(expUnix, 0), nil
}

func parseJWTClaims(rawJWT string) (map[string]any, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid jwt payload encoding: %w", err)
	}

	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid jwt payload: %s", err)
	}

	return claims, nil
}

func parseJWTNumericDate(value any) (int64, error) {
	switch v := value.(type) {
	case float64:
		if v != float64(int64(v)) {
			return 0, fmt.Errorf("unexpected non-integer value %v", v)
		}
		return int64(v), nil
	case json.Number:
		return v.Int64()
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case string:
		return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	default:
		return 0, fmt.Errorf("unexpected type %T", value)
	}
}

func createCacheDir(dirname string, debug bool) error {
	if debug {
		fmt.Printf("Checking if directory %s exists...\n", dirname)
	}
	if _, err := os.Stat(dirname); os.IsNotExist(err) {
		if debug {
			fmt.Printf("Failed to read the cache directory %s. Creating one.\n", dirname)
		}
		err := os.MkdirAll(dirname, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check directory: %v", err)
	} else {
		if debug {
			fmt.Printf("the cache directory %s exists.\n", dirname)
		}
	}
	return nil
}

func GetOIDCDiscovery(debug *bool) (string, string, error) {
	discoveryURL := strings.TrimSuffix(DEFAULT_OIDC_ISSUER, "/") + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to discover OIDC config from %s: %v", DEFAULT_OIDC_ISSUER, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("failed to discover OIDC config from %s: %s: %s", DEFAULT_OIDC_ISSUER, resp.Status, strings.TrimSpace(string(body)))
	}

	var discovery struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", "", fmt.Errorf("failed to parse OIDC provider endpoints: %v", err)
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" {
		return "", "", fmt.Errorf("OIDC discovery document from %s did not include authorization/token endpoints", DEFAULT_OIDC_ISSUER)
	}
	if *debug {
		fmt.Printf("Discovered authorization endpoint: %s\n", discovery.AuthorizationEndpoint)
		fmt.Printf("Discovered token endpoint: %s\n", discovery.TokenEndpoint)
	}

	return discovery.AuthorizationEndpoint, discovery.TokenEndpoint, nil
}

type authCodeResult struct {
	Code            string
	State           string
	AttestationData string
}

type oauthConfig struct {
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
	AuthURL       string
	TokenURL      string
	ResponseType  string
	State         string
	CodeVerifier  string
	CodeChallenge string
}

func buildOAuthConfig(authURL, tokenURL string) *oauthConfig {
	return &oauthConfig{
		ClientID:     DEFAULT_OIDC_CLIENT_ID,
		ClientSecret: DEFAULT_OIDC_CLIENT_SECRET,
		RedirectURL:  "http://127.0.0.1" + DEFAULT_OIDC_LISTEN_ADDRESS,
		Scopes:       strings.Split(DEFAULT_OIDC_SCOPES, " "),
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		ResponseType: "code",
	}
}

func buildPKCEOAuthConfig(authURL, tokenURL string) (*oauthConfig, error) {
	conf := buildOAuthConfig(authURL, tokenURL)
	state, err := generateOAuthState()
	if err != nil {
		return nil, err
	}
	conf.State = state

	codeVerifier, codeChallenge, err := generatePKCEParameters()
	if err != nil {
		return nil, err
	}
	conf.CodeVerifier = codeVerifier
	conf.CodeChallenge = codeChallenge
	return conf, nil
}

func generatePKCEParameters() (string, string, error) {
	verifierBytes := make([]byte, 32)
	if _, err := randomReadFunc(verifierBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate PKCE verifier: %v", err)
	}

	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return codeVerifier, codeChallenge, nil
}

func generateOAuthState() (string, error) {
	stateBytes := make([]byte, 32)
	if _, err := randomReadFunc(stateBytes); err != nil {
		return "", fmt.Errorf("failed to generate oauth state: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(stateBytes), nil
}

func buildAuthCodeURL(conf *oauthConfig, responseMode string) (string, error) {
	authURL, err := url.Parse(conf.AuthURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse auth URL: %v", err)
	}
	if strings.TrimSpace(conf.State) == "" {
		return "", fmt.Errorf("oauth state must not be empty")
	}

	query := authURL.Query()
	query.Set("client_id", conf.ClientID)
	query.Set("redirect_uri", conf.RedirectURL)
	responseType := strings.TrimSpace(conf.ResponseType)
	if responseType == "" {
		responseType = "code"
	}
	query.Set("response_type", responseType)
	query.Set("scope", strings.Join(conf.Scopes, " "))
	query.Set("state", conf.State)
	query.Set("access_type", "offline")
	if responseMode != "" {
		query.Set("response_mode", responseMode)
	}
	if conf.CodeChallenge != "" {
		query.Set("code_challenge", conf.CodeChallenge)
		query.Set("code_challenge_method", "S256")
	}
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

func exchangeAuthCode(conf *oauthConfig, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", conf.RedirectURL)
	form.Set("client_id", conf.ClientID)
	if conf.ClientSecret != "" {
		form.Set("client_secret", conf.ClientSecret)
	}
	if conf.CodeVerifier != "" {
		form.Set("code_verifier", conf.CodeVerifier)
	}

	req, err := http.NewRequest(http.MethodPost, conf.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	accessToken, err := parseAccessTokenResponse(resp.Body)
	if err != nil {
		return "", err
	}
	if err := storeAccessToken(accessToken); err != nil {
		return "", err
	}
	return accessToken, nil
}

func storeAccessToken(accessToken string) error {
	if accessToken == "" {
		return nil
	}

	accessTokenFilePath := getAccessTokenCachePath()
	err := createCacheDir(filepath.Dir(accessTokenFilePath), false)
	if err != nil {
		return err
	}
	err = os.WriteFile(accessTokenFilePath, []byte(accessToken), 0600)
	if err != nil {
		return fmt.Errorf("failed to store access token to: %s, error %s", accessTokenFilePath, err)
	}
	return nil
}

func parseAccessTokenResponse(body io.Reader) (string, error) {
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(body).Decode(&token); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}
	if token.AccessToken == "" {
		return "", fmt.Errorf("token response did not include access_token")
	}

	return token.AccessToken, nil
}

func parseAuthInput(raw string) (authCodeResult, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return authCodeResult{}, fmt.Errorf("authorization response is empty")
	}

	values, err := url.ParseQuery(raw)
	if err == nil && values.Get("code") != "" {
		return authCodeResult{
			Code:            values.Get("code"),
			State:           values.Get("state"),
			AttestationData: raw,
		}, nil
	}

	parsedURL, err := url.Parse(raw)
	if err == nil {
		if code := parsedURL.Query().Get("code"); code != "" {
			return authCodeResult{
				Code:            code,
				State:           parsedURL.Query().Get("state"),
				AttestationData: parsedURL.RawQuery,
			}, nil
		}
		if parsedURL.Fragment != "" {
			values, err := url.ParseQuery(parsedURL.Fragment)
			if err == nil {
				if code := values.Get("code"); code != "" {
					return authCodeResult{
						Code:            code,
						State:           values.Get("state"),
						AttestationData: parsedURL.Fragment,
					}, nil
				}
			}
		}
		if parsedURL.Scheme != "" && parsedURL.Host != "" {
			return authCodeResult{}, fmt.Errorf("authorization response URL did not include code")
		}
	}

	return authCodeResult{
		Code:            raw,
		AttestationData: raw,
	}, nil
}

func isBrowserURLInput(raw string) bool {
	parsedURL, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && parsedURL.Scheme != "" && parsedURL.Host != ""
}

func validateAuthCodeResult(result authCodeResult, expectedState string, required bool) error {
	if expectedState == "" {
		return nil
	}
	if result.State == "" {
		if required {
			return fmt.Errorf("authorization response did not include state")
		}
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(result.State), []byte(expectedState)) != 1 {
		return fmt.Errorf("authorization response state mismatch")
	}
	return nil
}

func getAuthCodeResult(conf *oauthConfig, responseMode *string) (authCodeResult, error) {
	if currentGOOS == "darwin" || currentGOOS == "windows" {
		authCodeURL, err := buildAuthCodeURL(conf, *responseMode)
		if err != nil {
			return authCodeResult{}, err
		}

		serverDone := make(chan authCodeResult, 1)
		serverErr := make(chan error, 1)
		go func() {
			result, err := waitForCodeServerFunc(DEFAULT_OIDC_LISTEN_ADDRESS)
			if err != nil {
				serverErr <- err
				return
			}
			serverDone <- result
		}()
		fmt.Printf("Your browser should open. If not, open this URL:\n%s\n\n", authCodeURL)
		_ = openBrowserFunc(authCodeURL)
		select {
		case err := <-serverErr:
			return authCodeResult{}, err
		case result := <-serverDone:
			if result.Code == "" {
				return authCodeResult{}, fmt.Errorf("no authorization code in callback")
			}
			if err := validateAuthCodeResult(result, conf.State, true); err != nil {
				return authCodeResult{}, err
			}
			return result, nil
		}
	}

	conf.RedirectURL = oidcOutOfBandRedirectURL
	authCodeURL, err := buildAuthCodeURL(conf, *responseMode)
	if err != nil {
		return authCodeResult{}, err
	}
	fmt.Printf("Open the following URL in your browser, log in, then paste the resulting authorization response here:\n%s\n", authCodeURL)
	fmt.Printf("\nPaste the authorization code displayed by the browser. If the provider returns a form body, paste the code=...&state=... payload.\n")
	fmt.Print("Enter the authorization code or payload: ")
	scanner := bufio.NewScanner(authCodeInputReader)
	if scanner.Scan() {
		input := scanner.Text()
		if isBrowserURLInput(input) {
			return authCodeResult{}, fmt.Errorf("manual authorization flow uses an out-of-band redirect; paste the authorization code displayed by the browser, not the browser URL")
		}
		result, err := parseAuthInput(input)
		if err != nil {
			return authCodeResult{}, err
		}
		if err := validateAuthCodeResult(result, conf.State, false); err != nil {
			return authCodeResult{}, err
		}
		return result, nil
	}
	if err := scanner.Err(); err != nil {
		return authCodeResult{}, fmt.Errorf("failed to read authorization response: %v", err)
	}
	return authCodeResult{}, fmt.Errorf("failed to read authorization response")
}

func buildAttestationData(result authCodeResult, codeVerifier string) string {
	values, err := url.ParseQuery(strings.TrimSpace(result.AttestationData))
	if err != nil || values.Get("code") == "" {
		values = url.Values{}
		values.Set("code", result.Code)
	}
	if codeVerifier != "" {
		values.Set("code_verifier", codeVerifier)
	}
	return values.Encode()
}

func buildAuthAttestationDataAndAccessToken(conf *oauthConfig, authResult authCodeResult, cachedAccessToken string, exchange func(*oauthConfig, string) (string, error)) (string, string, error) {
	attestationData := buildAttestationData(authResult, conf.CodeVerifier)
	if cachedAccessToken != "" {
		return attestationData, cachedAccessToken, nil
	}

	accessToken, err := exchange(conf, authResult.Code)
	if err != nil {
		return "", "", err
	}

	return attestationData, accessToken, nil
}

func startOIDCAuthCodeFlow(responseMode *string, debug *bool) (*oauthConfig, authCodeResult, error) {
	authURL, tokenURL, err := oidcDiscoveryFunc(debug)
	if err != nil {
		return nil, authCodeResult{}, err
	}

	conf, err := buildPKCEOAuthConfigFunc(authURL, tokenURL)
	if err != nil {
		return nil, authCodeResult{}, err
	}
	authResult, err := getAuthCodeResultFunc(conf, responseMode)
	if err != nil {
		return nil, authCodeResult{}, err
	}

	return conf, authResult, nil
}

func GetAuthAttestationData(responseMode *string, debug *bool) (string, error) {
	conf, authResult, err := startOIDCAuthCodeFlow(responseMode, debug)
	if err != nil {
		return "", err
	}

	return buildAttestationData(authResult, conf.CodeVerifier), nil
}

func GetAuthAttestationDataAndAccessToken(responseMode *string, debug *bool) (string, string, error) {
	accessToken, err := getCachedAccessToken(*debug)
	if *debug && err != nil {
		fmt.Printf("Failed get cached access token: %s\n", err)
	}
	if err != nil {
		accessToken = ""
	}

	conf, authResult, err := startOIDCAuthCodeFlow(responseMode, debug)
	if err != nil {
		return "", "", err
	}

	return buildAuthAttestationDataAndAccessToken(conf, authResult, accessToken, exchangeAuthCodeFunc)
}

func GetAuthAccessToken(responseMode *string, debug *bool) (string, error) {
	accessToken, err := getCachedAccessToken(*debug)
	if *debug && err != nil {
		fmt.Printf("Failed get cached access token: %s\n", err)
	}
	if accessToken != "" {
		return accessToken, err
	}

	conf, authResult, err := startOIDCAuthCodeFlow(responseMode, debug)
	if err != nil {
		return "", err
	}

	return exchangeAuthCodeFunc(conf, authResult.Code)
}

func GetPasswordGrantAccessToken(username, password string, debug *bool) (string, error) {
	if strings.TrimSpace(username) == "" {
		return "", fmt.Errorf("username is required")
	}
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("password is required")
	}

	_, tokenURL, err := oidcDiscoveryFunc(debug)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("client_id", DEFAULT_OIDC_CLIENT_ID)
	if DEFAULT_OIDC_CLIENT_SECRET != "" {
		form.Set("client_secret", DEFAULT_OIDC_CLIENT_SECRET)
	}
	if strings.TrimSpace(DEFAULT_OIDC_SCOPES) != "" {
		form.Set("scope", DEFAULT_OIDC_SCOPES)
	}

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create password grant token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("password grant token request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("password grant token request failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	accessToken, err := parseAccessTokenResponse(resp.Body)
	if err != nil {
		return "", err
	}
	if err := storeAccessToken(accessToken); err != nil {
		return "", err
	}
	return accessToken, nil
}

// waitForCodeServer runs a local HTTP server to capture the OAuth2 code via GET or POST.
// Returns the code and the raw callback payload.
func waitForCodeServer(listenAddress string) (authCodeResult, error) {
	codeCh := make(chan authCodeResult, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:              listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		result, err := authCodeResultFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "Login successful! You can close this tab.")
		codeCh <- result
	})

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("failed to listen for authorization callback: %v", err)
		}
	}()
	defer func() { time.Sleep(1 * time.Second); server.Close() }()

	select {
	case result := <-codeCh:
		return result, nil
	case err := <-errCh:
		return authCodeResult{}, err
	}
}

func authCodeResultFromRequest(r *http.Request) (authCodeResult, error) {
	var code, state, attestationData string
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return authCodeResult{}, fmt.Errorf("Failed to parse form")
		}
		code = r.FormValue("code")
		state = r.FormValue("state")
		attestationData = r.PostForm.Encode()
	} else {
		code = r.URL.Query().Get("code")
		state = r.URL.Query().Get("state")
		attestationData = r.URL.RawQuery
	}
	if code == "" {
		return authCodeResult{}, fmt.Errorf("No code in request")
	}

	return authCodeResult{
		Code:            code,
		State:           state,
		AttestationData: attestationData,
	}, nil
}

func GetUserNameFromAccessToken(rawJWT, userNameClaim string) (string, error) {
	claims, err := parseJWTClaims(rawJWT)
	if err != nil {
		return "", err
	}

	var userClaim string
	if userNameClaim != "" {
		userClaim = userNameClaim
	} else {
		userClaim = DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM
	}
	name, ok := claims[userClaim].(string)
	if !ok {
		return "", fmt.Errorf("no %s claim in jwt", userClaim)
	}
	return name, nil
}
