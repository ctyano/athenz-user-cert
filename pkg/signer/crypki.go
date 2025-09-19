package signer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var (
	DEFAULT_SIGNER_CRYPKI_SIGN_URL   = "http://localhost:10000/v3/sig/x509-cert/keys/x509-key"
	DEFAULT_SIGNER_CRYPKI_CA_URL     = "http://localhost:10000/v3/sig/x509-cert/keys/x509-key"
	DEFAULT_SIGNER_CRYPKI_VALIDITY   = "43200" // 30 * 24 * 60, 1 hour in seconds
	DEFAULT_SIGNER_CRYPKI_IDENTIFIER = "athenz"
	DEFAULT_SIGNER_CRYPKI_TIMEOUT    = "10" // in seconds
)

func SendCrypkiCSR(url string, csr string, headers *map[string][]string) (error, string) {
	type KeyMeta struct {
		Identifier string `json:"identifier"`
	}

	type RequestBody struct {
		CSR      string  `json:"csr"`
		KeyMeta  KeyMeta `json:"key_meta"`
		Validity int     `json:"validity"`
	}

	validity, _ := strconv.Atoi(strings.TrimSpace(DEFAULT_SIGNER_CRYPKI_VALIDITY))
	body := RequestBody{
		CSR: csr,
		KeyMeta: KeyMeta{
			Identifier: DEFAULT_SIGNER_CRYPKI_IDENTIFIER,
		},
		Validity: validity,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %s", err), ""
	}

	client, err := newSignerHTTPClient(DEFAULT_SIGNER_CRYPKI_TIMEOUT, DefaultSignerTLSCAPath())
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
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, url, body), ""
	}

	var response struct {
		Cert string `json:"cert"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %w", err), ""
	}

	return nil, response.Cert
}

func GetCrypkiRootCA(test bool, url string, headers *map[string][]string) (error, string) {
	client, err := newSignerHTTPClient(DEFAULT_SIGNER_CRYPKI_TIMEOUT, DefaultSignerTLSCAPath())
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
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, url, body), ""
	}

	var response struct {
		Cert string `json:"cert"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %w", err), ""
	}

	return nil, response.Cert
}
