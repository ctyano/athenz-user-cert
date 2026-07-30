package signer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	DEFAULT_SIGNER_ZTS_SIGN_URL                      = "https://127.0.0.1:4443/zts/v1"
	DEFAULT_SIGNER_ZTS_EXTERNAL_MEMBER_CERT_ENDPOINT = ""
	DEFAULT_SIGNER_ZTS_CA_URL                        = ""
	DEFAULT_SIGNER_ZTS_TIMEOUT                       = "10" // in seconds
)

const (
	ztsUserCertificatePath           = "/usercert"
	ztsExternalMemberCertificatePath = "/extmembercert"
)

// DefaultZTSUserCertificateEndpoint returns the configured ZTS base URL plus the user certificate path.
func DefaultZTSUserCertificateEndpoint() string {
	return ztsCertificateEndpoint(DEFAULT_SIGNER_ZTS_SIGN_URL, ztsUserCertificatePath)
}

// DefaultZTSExternalMemberCertEndpoint returns the configured endpoint or the ZTS base URL plus the external member certificate path.
func DefaultZTSExternalMemberCertEndpoint() string {
	if DEFAULT_SIGNER_ZTS_EXTERNAL_MEMBER_CERT_ENDPOINT != "" {
		return DEFAULT_SIGNER_ZTS_EXTERNAL_MEMBER_CERT_ENDPOINT
	}
	return ztsCertificateEndpoint(DEFAULT_SIGNER_ZTS_SIGN_URL, ztsExternalMemberCertificatePath)
}

func ztsCertificateEndpoint(baseOrEndpoint, certificatePath string) string {
	endpoint := strings.TrimRight(strings.TrimSpace(baseOrEndpoint), "/")
	switch {
	case strings.HasSuffix(endpoint, ztsUserCertificatePath):
		return strings.TrimSuffix(endpoint, ztsUserCertificatePath) + certificatePath
	case strings.HasSuffix(endpoint, ztsExternalMemberCertificatePath):
		return strings.TrimSuffix(endpoint, ztsExternalMemberCertificatePath) + certificatePath
	default:
		return endpoint + certificatePath
	}
}

// SendZTSCSR sends a CSR to the Athenz ZTS user certificate endpoint.
func SendZTSCSR(name string, endpoint string, csr string, attestationData string, signerTLSCAPath string, headers *map[string][]string) (error, string) {
	return sendZTSCertificateRequest(endpoint, ztsUserCertificateRequest{
		Name:            name,
		CSR:             csr,
		AttestationData: attestationData,
	}, signerTLSCAPath, headers, &ztsUserCertificate{})
}

// SendZTSExternalMemberCertCSR sends a CSR to the Athenz ZTS external member certificate endpoint.
func SendZTSExternalMemberCertCSR(name string, endpoint string, csr string, attestationData string, signerTLSCAPath string, headers *map[string][]string) (error, string) {
	return sendZTSCertificateRequest(endpoint, ztsExternalMemberCertificateRequest{
		Name:            name,
		CSR:             csr,
		AttestationData: attestationData,
	}, signerTLSCAPath, headers, &ztsExternalMemberCertificate{})
}

type ztsUserCertificateRequest struct {
	Name                string `json:"name"`
	CSR                 string `json:"csr"`
	AttestationData     string `json:"attestationData"`
	ExpiryTime          *int32 `json:"expiryTime,omitempty"`
	X509CertSignerKeyID string `json:"x509CertSignerKeyId,omitempty"`
}

type ztsExternalMemberCertificateRequest struct {
	Name                string `json:"name"`
	CSR                 string `json:"csr"`
	AttestationData     string `json:"attestationData"`
	ExpiryTime          *int32 `json:"expiryTime,omitempty"`
	X509CertSignerKeyID string `json:"x509CertSignerKeyId,omitempty"`
}

type ztsCertificateResponse interface {
	certificate() string
}

type ztsUserCertificate struct {
	X509Certificate string `json:"x509Certificate"`
}

func (cert *ztsUserCertificate) certificate() string {
	return cert.X509Certificate
}

type ztsExternalMemberCertificate struct {
	X509Certificate string `json:"x509Certificate"`
}

func (cert *ztsExternalMemberCertificate) certificate() string {
	return cert.X509Certificate
}

func sendZTSCertificateRequest(endpoint string, body any, signerTLSCAPath string, headers *map[string][]string, response ztsCertificateResponse) (error, string) {
	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %s", err), ""
	}

	client, err := newSignerHTTPClient(DEFAULT_SIGNER_ZTS_TIMEOUT, signerTLSCAPath)
	if err != nil {
		return err, ""
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
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
		if strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
			return fmt.Errorf("Failed to send request: %s (set -signer-tls-ca to the signer server CA PEM path if this is the first direct ZTS request)", err), ""
		}
		return fmt.Errorf("Failed to send request: %s", err), ""
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, endpoint, strings.TrimSpace(string(body))), ""
	}

	if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %w", err), ""
	}

	cert := response.certificate()
	if strings.TrimSpace(cert) == "" {
		return fmt.Errorf("Failed to parse JSON response: x509Certificate is missing"), ""
	}

	return nil, cert
}

// GetZTSRootCA returns the signer-issued CA bundle from a remote endpoint.
func GetZTSRootCA(test bool, source string, headers *map[string][]string) (error, string) {
	if strings.TrimSpace(source) == "" {
		return nil, ""
	}

	client, err := newSignerHTTPClient(DEFAULT_SIGNER_ZTS_TIMEOUT, DefaultSignerTLSCAPath())
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
