package signer

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	athenzzts "github.com/AthenZ/athenz/clients/go/zts"
)

var (
	DEFAULT_SIGNER_ZTS_SIGN_URL = "https://127.0.0.1:4443/zts/v1/usercert"
	DEFAULT_SIGNER_ZTS_CA_URL   = ""
	DEFAULT_SIGNER_ZTS_TIMEOUT  = "10" // in seconds
)

// SendZTSCSR sends a CSR to the Athenz ZTS user certificate endpoint.
func SendZTSCSR(name string, endpoint string, csr string, attestationData string, signerTLSCAPath string, headers *map[string][]string) (error, string) {
	client, err := newZTSClient(ztsBaseURLFromUserCertEndpoint(endpoint), DEFAULT_SIGNER_ZTS_TIMEOUT, signerTLSCAPath, "", nil, headers)
	if err != nil {
		return err, ""
	}

	userCert, err := client.PostUserCertificateRequest(&athenzzts.UserCertificateRequest{
		Name:            name,
		Csr:             csr,
		AttestationData: attestationData,
	})
	if err != nil {
		return formatZTSClientError(err, endpoint), ""
	}
	if userCert == nil {
		return fmt.Errorf("Failed to parse JSON response: empty user certificate response"), ""
	}

	return nil, userCert.X509Certificate
}

// GetZTSRootCA returns the signer-issued CA bundle from a remote endpoint.
func GetZTSRootCA(test bool, source string, headers *map[string][]string) (error, string) {
	return getZTSRootCA(test, source, DefaultSignerTLSCAPath(), "", nil, headers)
}

// GetZTSRootCAWithClientCert returns the signer-issued CA bundle using the previously issued client certificate for mTLS.
func GetZTSRootCAWithClientCert(test bool, source string, signerTLSCAPath string, clientCertPEM string, privateKey crypto.PrivateKey, headers *map[string][]string) (error, string) {
	return getZTSRootCA(test, source, signerTLSCAPath, clientCertPEM, privateKey, headers)
}

func getZTSRootCA(test bool, source string, signerTLSCAPath string, clientCertPEM string, privateKey crypto.PrivateKey, headers *map[string][]string) (error, string) {
	if strings.TrimSpace(source) == "" {
		return nil, ""
	}

	if baseURL, bundleName, ok := ztsCABundleEndpoint(source); ok {
		client, err := newZTSClient(baseURL, DEFAULT_SIGNER_ZTS_TIMEOUT, signerTLSCAPath, clientCertPEM, privateKey, headers)
		if err != nil {
			return err, ""
		}
		bundle, err := client.GetCertificateAuthorityBundle(bundleName)
		if err != nil {
			if test {
				if status, ok := ztsErrorStatusCode(err); ok && status == http.StatusUnauthorized {
					return nil, ""
				}
			}
			return formatZTSClientError(err, source), ""
		}
		if bundle == nil {
			if test {
				return nil, ""
			}
			return fmt.Errorf("No CA certificate bundle found in response from %s", source), ""
		}
		return nil, bundle.Certs
	}

	return getZTSRootCAHTTP(test, source, signerTLSCAPath, clientCertPEM, privateKey, headers)
}

func getZTSRootCAHTTP(test bool, source string, signerTLSCAPath string, clientCertPEM string, privateKey crypto.PrivateKey, headers *map[string][]string) (error, string) {
	client, err := newSignerHTTPClientWithClientCert(DEFAULT_SIGNER_ZTS_TIMEOUT, signerTLSCAPath, clientCertPEM, privateKey)
	if err != nil {
		return err, ""
	}

	req, err := http.NewRequest("GET", source, bytes.NewBuffer(nil))
	if err != nil {
		return fmt.Errorf("Failed to create request: %s", err), ""
	}

	req.Header.Set("Content-Type", "application/json")
	if headers != nil {
		for key, values := range *headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to send request: %s", err), ""
	}
	defer resp.Body.Close()

	if test && resp.StatusCode == http.StatusUnauthorized {
		return nil, ""
	}

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, source, strings.TrimSpace(string(body))), ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to read response body: %w", err), ""
	}

	caPEM, err := parseZTSRootCAResponse(body, source, test)
	if err != nil {
		return err, ""
	}

	return nil, caPEM
}

func newZTSClient(baseURL string, timeoutValue string, signerTLSCAPath string, clientCertPEM string, privateKey crypto.PrivateKey, headers *map[string][]string) (athenzzts.ZTSClient, error) {
	httpClient, err := newSignerHTTPClientWithClientCert(timeoutValue, signerTLSCAPath, clientCertPEM, privateKey)
	if err != nil {
		return athenzzts.ZTSClient{}, err
	}

	transport := httpClient.Transport
	if headers != nil {
		if transport == nil {
			transport = http.DefaultTransport
		}
		transport = headerRoundTripper{
			base:    transport,
			headers: headers,
		}
	}

	client := athenzzts.NewClient(strings.TrimRight(baseURL, "/"), transport)
	client.Timeout = httpClient.Timeout
	return client, nil
}

type headerRoundTripper struct {
	base    http.RoundTripper
	headers *map[string][]string
}

func (rt headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	for key, values := range *rt.headers {
		for _, value := range values {
			cloned.Header.Add(key, value)
		}
	}
	return rt.base.RoundTrip(cloned)
}

func ztsBaseURLFromUserCertEndpoint(endpoint string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	return strings.TrimSuffix(trimmed, "/usercert")
}

func ztsCABundleEndpoint(source string) (string, athenzzts.SimpleName, bool) {
	parsed, err := url.Parse(strings.TrimSpace(source))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", false
	}

	trimmedPath := strings.TrimRight(parsed.Path, "/")
	marker := "/cacerts/"
	idx := strings.LastIndex(trimmedPath, marker)
	if idx < 0 {
		return "", "", false
	}

	bundleName := strings.TrimPrefix(trimmedPath[idx:], marker)
	if bundleName == "" || strings.Contains(bundleName, "/") {
		return "", "", false
	}
	if unescaped, err := url.PathUnescape(bundleName); err == nil {
		bundleName = unescaped
	}

	parsed.Path = strings.TrimRight(trimmedPath[:idx], "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), athenzzts.SimpleName(bundleName), true
}

func formatZTSClientError(err error, requestURL string) error {
	if strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
		return fmt.Errorf("Failed to send request: %s (set -signer-tls-ca to the signer server CA PEM path if this is the first direct ZTS request)", err)
	}
	if status, ok := ztsErrorStatusCode(err); ok {
		statusText := fmt.Sprintf("%d", status)
		if text := http.StatusText(status); text != "" {
			statusText += " " + text
		}
		response := strings.TrimSpace(strings.TrimPrefix(err.Error(), fmt.Sprintf("%d ", status)))
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", statusText, requestURL, response)
	}
	return fmt.Errorf("Failed to send request: %s", err)
}

type statusCoder interface {
	StatusCode() int
}

func ztsErrorStatusCode(err error) (int, bool) {
	statusErr, ok := err.(statusCoder)
	if !ok {
		return 0, false
	}
	status := statusErr.StatusCode()
	return status, status > 0
}

func parseZTSRootCAResponse(body []byte, source string, test bool) (string, error) {
	rawBody := strings.TrimSpace(string(body))
	if strings.HasPrefix(rawBody, "-----BEGIN CERTIFICATE-----") {
		return rawBody, nil
	}

	var response struct {
		Name                  string `json:"name"`
		X509CertificateSigner string `json:"x509CertificateSigner"`
		CACertBundle          string `json:"caCertBundle"`
		CACertificates        string `json:"caCertificates"`
		Certs                 string `json:"certs"`
		Certificate           string `json:"certificate"`
		Cert                  string `json:"cert"`
		Result                struct {
			Certificate string `json:"certificate"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		if test {
			return "", nil
		}
		return "", fmt.Errorf("Failed to parse JSON response: %w", err)
	}

	switch {
	case strings.TrimSpace(response.X509CertificateSigner) != "":
		return response.X509CertificateSigner, nil
	case strings.TrimSpace(response.CACertBundle) != "":
		return response.CACertBundle, nil
	case strings.TrimSpace(response.CACertificates) != "":
		return response.CACertificates, nil
	case strings.TrimSpace(response.Certs) != "":
		return response.Certs, nil
	case strings.TrimSpace(response.Certificate) != "":
		return response.Certificate, nil
	case strings.TrimSpace(response.Cert) != "":
		return response.Cert, nil
	case strings.TrimSpace(response.Result.Certificate) != "":
		return response.Result.Certificate, nil
	case test:
		return "", nil
	default:
		return "", fmt.Errorf("No CA certificate bundle found in response from %s", source)
	}
}
