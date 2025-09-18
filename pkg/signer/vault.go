package signer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	DEFAULT_SIGNER_VAULT_SIGN_URL   = "http://localhost:10000/v1/pki/issuer/default/sign/issuers"
	DEFAULT_SIGNER_VAULT_CA_URL     = "http://localhost:10000/v1/pki/ca_chain"
	DEFAULT_SIGNER_VAULT_ISSUER_REF = "default"
	DEFAULT_SIGNER_VAULT_TTL        = "30d"
	DEFAULT_SIGNER_VAULT_TIMEOUT    = "10" // in seconds
)

// SendVaultCSR sends a CSR to the Vault server to issue an certificate
// Vault API reference:
// https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-certificate
func SendVaultCSR(commonName string, url string, csr string, headers *map[string][]string) (error, string) {
	type RequestBody struct {
		CSR        string `json:"csr"`
		CommonName string `json:"common_name"`
		IssuerRef  string `json:"issuer_ref"`
		TTL        string `json:"ttl"`
	}

	body := RequestBody{
		CSR:        csr,
		CommonName: commonName,
		IssuerRef:  DEFAULT_SIGNER_VAULT_ISSUER_REF,
		TTL:        DEFAULT_SIGNER_VAULT_TTL,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %s", err), ""
	}

	timeout, _ := strconv.Atoi(strings.TrimSpace(DEFAULT_SIGNER_VAULT_TIMEOUT))
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
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

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, url, body), ""
	}

	type data struct {
		Uxpiration  string   `json:"expiration"`
		Certificate string   `json:"certificate"`
		CA          string   `json:"issuing_ca"`
		CAChain     []string `json:"ca_chain"`
		Serial      string   `json:"serial_number"`
	}

	var response struct {
		Data data `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %w", err), ""
	}

	return nil, response.Data.Certificate
}

// GetVaultRootCA gets issuer certificate from the Vault server
// Vault API reference:
// https://developer.hashicorp.com/vault/api-docs/secret/pki#read-default-issuer-certificate-chain
// https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer-certificate
func GetVaultRootCA(test bool, url string, headers *map[string][]string) (error, string) {
	timeout, _ := strconv.Atoi(strings.TrimSpace(DEFAULT_SIGNER_VAULT_TIMEOUT))
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", url, bytes.NewBuffer(nil))
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
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, url, body), ""
	}

	type data struct {
		Certificate string   `json:"certificate"`
		CAChain     []string `json:"ca_chain"`
	}

	var response struct {
		Data data `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %w", err), ""
	}

	return nil, response.Data.Certificate
}
