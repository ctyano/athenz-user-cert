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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	oidcOutOfBandRedirectURL                  = "urn:ietf:wg:oauth:2.0:oob"
	defaultOIDCAccessTokenCacheExpiryMinutes  = int64(15)
	defaultOIDCAccessTokenCacheExpiryDuration = time.Duration(defaultOIDCAccessTokenCacheExpiryMinutes) * time.Minute
)

var (
	DEFAULT_OIDC_CLIENT_ID                         = "athenz-user-cert"
	DEFAULT_OIDC_CLIENT_SECRET                     = "athenz-user-cert"
	DEFAULT_OIDC_ISSUER                            = "http://127.0.0.1:5556/dex"
	DEFAULT_OIDC_SCOPES                            = "openid email profile"
	DEFAULT_OIDC_LISTEN_ADDRESS                    = ":8080"
	DEFAULT_OIDC_ACCESS_TOKEN_PATH                 = ".athenz/.accesstoken"
	DEFAULT_OIDC_ACCESS_TOKEN_CACHE_EXPIRY_MINUTES = "15"
	DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM          = "name"
	DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM             = "name"
	DEFAULT_OIDC_CLOSE_WINDOW_DELAY                = "0" // seconds; 0 disables auto-close of the callback tab

	maxPortSearchAttempts = 100

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
	waitForCodeServerFunc = waitForCodeServer
	closeBrowserTabFunc   = closeBrowserTab
	reservePortFunc       = reserveCallbackListener
	osascriptStartFunc    = func(script string) error {
		return exec.Command("/usr/bin/osascript", "-e", script).Start()
	}
	oidcDiscoveryFunc        = GetOIDCDiscovery
	buildPKCEOAuthConfigFunc = buildPKCEOAuthConfig
	getAuthCodeResultFunc    = getAuthCodeResult
	exchangeAuthCodeFunc     = exchangeAuthCode
	randomReadFunc           = rand.Read
)

func closeWindowDelaySeconds() int {
	delay, err := strconv.Atoi(strings.TrimSpace(DEFAULT_OIDC_CLOSE_WINDOW_DELAY))
	if err != nil || delay < 0 {
		return 0
	}
	return delay
}

// listenAddressBasePort extracts the port number from an OIDC listen address
// such as ":8080" or "127.0.0.1:8080".
func listenAddressBasePort(listenAddress string) (int, error) {
	listenAddress = strings.TrimSpace(listenAddress)
	if listenAddress == "" {
		return 0, fmt.Errorf("OIDC listen address is empty")
	}
	_, portString, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return 0, fmt.Errorf("failed to parse OIDC listen address %q: %v", listenAddress, err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return 0, fmt.Errorf("failed to parse OIDC listen port %q: %v", portString, err)
	}
	return port, nil
}

// reserveCallbackListener binds a local callback listener, retrying on the
// next port number when the requested port is already in use (up to
// maxPortSearchAttempts). The returned listener stays open so the callback
// server can serve on it without a check-to-use race.
func reserveCallbackListener(basePort int) (net.Listener, int, error) {
	for attempt := 0; attempt < maxPortSearchAttempts; attempt++ {
		port := basePort + attempt
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return listener, port, nil
		}
		if !isAddressInUse(err) {
			return nil, 0, fmt.Errorf("failed to bind callback server to 127.0.0.1:%d: %v", port, err)
		}
	}
	return nil, 0, fmt.Errorf("no free callback port found starting at %d after %d attempts", basePort, maxPortSearchAttempts)
}

func isAddressInUse(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		err = opErr.Err
	}
	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) {
		err = syscallErr.Err
	}
	return errors.Is(err, syscall.EADDRINUSE)
}

// closeBrowserTab closes any Chrome or Safari tab whose URL starts with
// urlPrefix. Browsers commonly refuse the success page's own window.close()
// for tabs they consider not script-opened, so this reliably closes the
// callback tab on macOS; on other platforms it is a no-op and the page's
// countdown is the only close attempt. The AppleScript waits delaySecs+0.5
// seconds before acting (letting the page countdown play out) and runs
// detached (Start, no Wait) so it outlives the calling process. Errors are
// written to stderr and otherwise ignored — this is best-effort cleanup. The
// first run may trigger a one-time macOS Automation permission prompt,
// attributed to the user's terminal application.
func closeBrowserTab(urlPrefix string, delaySecs int) {
	if currentGOOS != "darwin" {
		return
	}
	script := fmt.Sprintf(`delay %.1f
set theURL to %q
tell application "System Events"
	set runningApps to name of every process
end tell
if "Google Chrome" is in runningApps then
	tell application "Google Chrome"
		repeat with w in every window
			repeat with t in every tab of w
				if URL of t starts with theURL then
					close t
				end if
			end repeat
		end repeat
	end tell
end if
if "Safari" is in runningApps then
	tell application "Safari"
		repeat with w in every window
			repeat with t in every tab of w
				if URL of t starts with theURL then
					close t
				end if
			end repeat
		end repeat
	end tell
end if`, float64(delaySecs)+0.5, urlPrefix)

	if err := osascriptStartFunc(script); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start browser tab close: %v\n", err)
	}
}

// closeWindowHTML returns the HTML page served after a successful OIDC
// callback. When closeWindowDelay > 0 the page shows a live countdown and
// attempts to close its own tab via window.close() when the countdown reaches
// zero; otherwise it shows a static "You may close this window now" message.
// window.close() is best-effort: some browsers only honor it for script-opened
// tabs, in which case the message is reset to the static close instruction
// before the close attempt so the page stays accurate.
func closeWindowHTML(closeWindowDelay int) string {
	closeMsg := "You may close this window now."
	closeScript := ""
	if closeWindowDelay > 0 {
		unit := "seconds"
		if closeWindowDelay == 1 {
			unit = "second"
		}
		closeMsg = fmt.Sprintf("This window will close in %d %s.", closeWindowDelay, unit)
		closeScript = fmt.Sprintf(closeWindowScriptTemplate, closeWindowDelay)
	}
	return strings.NewReplacer(
		"__CLOSE_MSG__", closeMsg,
		"__CLOSE_SCRIPT__", closeScript,
	).Replace(closeWindowHTMLTemplate)
}

const closeWindowScriptTemplate = `  <script>
    (function() {
      var secs = %d;
      var el = document.getElementById('close-msg');
      var iv = setInterval(function() {
        secs--;
        if (secs <= 0) {
          clearInterval(iv);
          el.textContent = 'You may close this window now.';
          window.close();
        } else {
          el.textContent = 'This window will close in ' + secs + ' second' + (secs === 1 ? '' : 's') + '.';
        }
      }, 1000);
    })();
  </script>
`

const closeWindowHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
  <style>
    body {
      display: flex;
      justify-content: center;
      margin: 0;
    }

    .message-box {
      border: 0.125em solid purple;
      padding: 1em;
      margin: 1.25em 0;
      font-family: Arial, sans-serif;
      color: #333;
      background-color: #f9f4ff;
      border-radius: 0.5em;
      display: table;
      width: 90%;
      max-width: 50em;
      box-sizing: border-box;
      text-align: center;
      font-size: 1.25em;
      line-height: 1.4;
    }

    .small-text {
      font-size: 0.75em;
      display: block;
      margin-top: 0.25em;
    }

  </style>
</head>
<body>
  <div class="message-box">
    <b>Authentication successful.</b><br>
    <span class="small-text" id="close-msg">__CLOSE_MSG__</span>
  </div>
__CLOSE_SCRIPT__</body>
</html>`

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
	claims, err := parseJWTClaims(accessToken)
	if err != nil {
		return false, err
	}

	expiry, err := getJWTExpiry(claims)
	if err != nil {
		return false, fmt.Errorf("could not parse cached access token: %v", err)
	}
	issueTime, err := getJWTIssueTime(claims)
	if err != nil {
		return false, fmt.Errorf("could not parse cached access token: %v", err)
	}

	cacheExpiry := issueTime.Add(accessTokenCacheExpiryDuration())

	if debug {
		fmt.Printf("Cached access token issued at %s\n", issueTime.UTC().Format(time.RFC3339))
		fmt.Printf("Cached access token expires at %s\n", expiry.UTC().Format(time.RFC3339))
		fmt.Printf("Cached access token cache expires at %s\n", cacheExpiry.UTC().Format(time.RFC3339))
	}

	now := time.Now()
	return !now.Before(expiry) || !now.Before(cacheExpiry), nil
}

func accessTokenCacheExpiryDuration() time.Duration {
	minutes, err := parseAccessTokenCacheExpiryMinutes(DEFAULT_OIDC_ACCESS_TOKEN_CACHE_EXPIRY_MINUTES)
	if err != nil {
		return defaultOIDCAccessTokenCacheExpiryDuration
	}
	return time.Duration(minutes) * time.Minute
}

func parseAccessTokenCacheExpiryMinutes(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultOIDCAccessTokenCacheExpiryMinutes, nil
	}
	minutes, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, err
	}
	if minutes <= 0 {
		return 0, fmt.Errorf("must be positive")
	}
	return minutes, nil
}

func getJWTExpiry(claims map[string]any) (time.Time, error) {
	return getJWTNumericDateClaim(claims, "exp")
}

func getJWTIssueTime(claims map[string]any) (time.Time, error) {
	return getJWTNumericDateClaim(claims, "iat")
}

func getJWTNumericDateClaim(claims map[string]any, name string) (time.Time, error) {
	claim, ok := claims[name]
	if !ok {
		return time.Time{}, fmt.Errorf("no %s claim in jwt", name)
	}

	unixTime, err := parseJWTNumericDate(claim)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s claim in jwt: %v", name, err)
	}

	return time.Unix(unixTime, 0), nil
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

func parseManualAuthCode(raw string) (authCodeResult, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return authCodeResult{}, fmt.Errorf("authorization code is empty")
	}
	if isManualURLInput(raw) {
		return authCodeResult{}, fmt.Errorf("manual authorization flow uses an out-of-band redirect; paste only the authorization code displayed by the browser")
	}

	values := url.Values{}
	values.Set("code", raw)
	return authCodeResult{
		Code:            raw,
		AttestationData: values.Encode(),
	}, nil
}

func isManualURLInput(raw string) bool {
	parsedURL, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && parsedURL.Scheme != "" && (parsedURL.Host != "" || parsedURL.Scheme == "urn")
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
		closeWindowDelay := closeWindowDelaySeconds()

		basePort, err := listenAddressBasePort(DEFAULT_OIDC_LISTEN_ADDRESS)
		if err != nil {
			return authCodeResult{}, err
		}
		listener, port, err := reservePortFunc(basePort)
		if err != nil {
			return authCodeResult{}, err
		}
		defer listener.Close()

		conf.RedirectURL = fmt.Sprintf("http://127.0.0.1:%d", port)
		authCodeURL, err := buildAuthCodeURL(conf, *responseMode)
		if err != nil {
			return authCodeResult{}, err
		}

		serverDone := make(chan authCodeResult, 1)
		serverErr := make(chan error, 1)
		go func() {
			result, err := waitForCodeServerFunc(listener, closeWindowDelay)
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
			if closeWindowDelay > 0 {
				closeBrowserTabFunc(fmt.Sprintf("http://127.0.0.1:%d", port), closeWindowDelay)
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
	fmt.Printf("Open the following URL in your browser and log in:\n%s\n", authCodeURL)
	fmt.Printf("\nPaste the authorization code displayed by the browser.\n")
	fmt.Print("Enter the authorization code: ")
	scanner := bufio.NewScanner(authCodeInputReader)
	if scanner.Scan() {
		result, err := parseManualAuthCode(scanner.Text())
		if err != nil {
			return authCodeResult{}, err
		}
		if err := validateAuthCodeResult(result, conf.State, false); err != nil {
			return authCodeResult{}, err
		}
		return result, nil
	}
	if err := scanner.Err(); err != nil {
		return authCodeResult{}, fmt.Errorf("failed to read authorization code: %v", err)
	}
	return authCodeResult{}, fmt.Errorf("failed to read authorization code")
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

// waitForCodeServer runs a local HTTP server on the given listener to capture
// the OAuth2 code via GET or POST. When closeWindowDelay > 0 the success page
// auto-closes its own tab after a countdown. Returns the code and the raw
// callback parameters.
func waitForCodeServer(listener net.Listener, closeWindowDelay int) (authCodeResult, error) {
	codeCh := make(chan authCodeResult, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		result, err := authCodeResultFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, closeWindowHTML(closeWindowDelay))
		codeCh <- result
	})

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

func GetExternalIDFromAccessToken(rawJWT, externalIDClaim string) (string, error) {
	return getStringClaimFromAccessToken(rawJWT, externalIDClaim, DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM)
}

func GetUserNameFromAccessToken(rawJWT, userNameClaim string) (string, error) {
	return getStringClaimFromAccessToken(rawJWT, userNameClaim, DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM)
}

func getStringClaimFromAccessToken(rawJWT, claimName, defaultClaimName string) (string, error) {
	claims, err := parseJWTClaims(rawJWT)
	if err != nil {
		return "", err
	}

	var claim string
	if claimName != "" {
		claim = claimName
	} else {
		claim = defaultClaimName
	}
	value, ok := claims[claim].(string)
	if !ok {
		return "", fmt.Errorf("no %s claim in jwt", claim)
	}
	return value, nil
}
