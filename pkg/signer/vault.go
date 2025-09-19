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
	DEFAULT_SIGNER_VAULT_JWT_LOGIN_URL = "http://localhost:10000/v1/auth/jwt/login"
	DEFAULT_SIGNER_VAULT_JWT_ROLE      = "jwt"
	DEFAULT_SIGNER_VAULT_PKI_NAME      = "rootca"
	DEFAULT_SIGNER_VAULT_PKI_ROLE      = "issuers"
	DEFAULT_SIGNER_VAULT_SIGN_URL      = "http://localhost:10000/v1/" + DEFAULT_SIGNER_VAULT_PKI_NAME + "/sign/" + DEFAULT_SIGNER_VAULT_PKI_ROLE
	DEFAULT_SIGNER_VAULT_CA_URL        = "http://localhost:10000/v1/" + DEFAULT_SIGNER_VAULT_PKI_NAME + "/cert/ca_chain"
	DEFAULT_SIGNER_VAULT_ISSUER_REF    = "default"
	DEFAULT_SIGNER_VAULT_TTL           = "1 hour"
	DEFAULT_SIGNER_VAULT_TIMEOUT       = "10" // in seconds
)

func GetVaultToken(url string, role string, jwt string, headers *map[string][]string) (error, string) {
	type RequestBody struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}

	body := RequestBody{
		Role: role,
		JWT:  jwt,
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

	type auth struct {
		ClientToken string `json:"client_token"`
	}

	var response struct {
		Auth auth `json:"auth"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %w", err), ""
	}

	return nil, response.Auth.ClientToken
}

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
		Expiration  int      `json:"expiration"`
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
		Certificate           string `json:"certificate"`
		CAChain               string `json:"ca_chain"`
		IssuedID              string `json:"issuer_id"`
		RevocationTime        int    `json:"revocation_time"`
		RevocationTimeRFC3339 string `json:"revocation_time_rfc3339"`
	}

	var response struct {
		Data data `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Failed to parse JSON response: %w, respose: %#v", err, body), ""
	}

	return nil, response.Data.CAChain
}
