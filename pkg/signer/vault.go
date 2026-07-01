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
	DEFAULT_SIGNER_VAULT_JWT_LOGIN_URL = "http://localhost:10000/v1/auth/jwt/login"
	DEFAULT_SIGNER_VAULT_JWT_ROLE      = "jwt"
	DEFAULT_SIGNER_VAULT_PKI_NAME      = "rootca"
	DEFAULT_SIGNER_VAULT_PKI_ROLE      = "issuers"
	DEFAULT_SIGNER_VAULT_SIGN_URL      = "http://localhost:10000/v1/" + DEFAULT_SIGNER_VAULT_PKI_NAME + "/sign/" + DEFAULT_SIGNER_VAULT_PKI_ROLE
	DEFAULT_SIGNER_VAULT_CA_URL        = "http://localhost:10000/v1/" + DEFAULT_SIGNER_VAULT_PKI_NAME + "/cert/ca_chain"
	DEFAULT_SIGNER_VAULT_ISSUER_REF    = "default"
	DEFAULT_SIGNER_VAULT_TTL           = "1h"
	DEFAULT_SIGNER_VAULT_TIMEOUT       = "10" // in seconds
)

func GetVaultToken(url string, role string, jwt string, headers *map[string][]string) (error, string) {
	body := map[string]string{
		"role": role,
		"jwt":  jwt,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %s", err), ""
	}

	client, err := newSignerHTTPClient(DEFAULT_SIGNER_VAULT_TIMEOUT, DefaultSignerTLSCAPath())
	if err != nil {
		return err, ""
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
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, url, strings.TrimSpace(string(body))), ""
	}

	var response struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %w", err), ""
	}

	return nil, response.Auth.ClientToken
}

// https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-certificate
func SendVaultCSR(commonName string, url string, csr string, headers *map[string][]string) (error, string) {
	body := map[string]string{
		"csr":         csr,
		"common_name": commonName,
		"issuer_ref":  DEFAULT_SIGNER_VAULT_ISSUER_REF,
		"ttl":         DEFAULT_SIGNER_VAULT_TTL,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %s", err), ""
	}

	client, err := newSignerHTTPClient(DEFAULT_SIGNER_VAULT_TIMEOUT, DefaultSignerTLSCAPath())
	if err != nil {
		return err, ""
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
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, url, strings.TrimSpace(string(body))), ""
	}

	var response struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %w", err), ""
	}

	return nil, response.Data.Certificate
}

// https://developer.hashicorp.com/vault/api-docs/secret/pki#read-default-issuer-certificate-chain
// https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer-certificate
func GetVaultRootCA(test bool, url string, headers *map[string][]string) (error, string) {
	client, err := newSignerHTTPClient(DEFAULT_SIGNER_VAULT_TIMEOUT, DefaultSignerTLSCAPath())
	if err != nil {
		return err, ""
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
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, url, strings.TrimSpace(string(body))), ""
	}

	var response struct {
		Data struct {
			CAChain string `json:"ca_chain"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Failed to parse JSON response: %w, response: %#v", err, string(body)), ""
	}

	return nil, response.Data.CAChain
}
