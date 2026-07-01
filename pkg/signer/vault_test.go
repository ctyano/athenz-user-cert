package signer

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestGetVaultToken(t *testing.T) {
	headers := map[string][]string{
		"X-Custom": {"custom-value"},
	}

	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("X-Custom"); got != "custom-value" {
			t.Fatalf("expected custom header, got %q", got)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		var payload struct {
			Role string `json:"role"`
			JWT  string `json:"jwt"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to unmarshal request body: %v", err)
		}
		if payload.Role != "myrole" {
			t.Fatalf("expected role 'myrole', got %q", payload.Role)
		}
		if payload.JWT != "myjwt" {
			t.Fatalf("expected jwt 'myjwt', got %q", payload.JWT)
		}

		return jsonResponse(http.StatusOK, `{"auth":{"client_token":"vault-token"}}`), nil
	})
	defer restore()

	err, token := GetVaultToken("stub://vault.example/auth", "myrole", "myjwt", &headers)
	if err != nil {
		t.Fatalf("GetVaultToken returned error: %v", err)
	}
	if token != "vault-token" {
		t.Fatalf("expected token 'vault-token', got %q", token)
	}
}

func TestGetVaultTokenHandlesErrorResponse(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, `{"errors":["invalid jwt"]}`), nil
	})
	defer restore()

	err, token := GetVaultToken("stub://vault.example/auth", "myrole", "bad-jwt", nil)
	if err == nil {
		t.Fatal("expected GetVaultToken to return an error")
	}
	if token != "" {
		t.Fatalf("expected no token on error, got %q", token)
	}
}

func TestGetVaultTokenAdditionalErrors(t *testing.T) {
	t.Run("invalid request url", func(t *testing.T) {
		err, _ := GetVaultToken("://bad-url", "myrole", "myjwt", nil)
		if err == nil {
			t.Fatal("expected invalid URL to return an error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return nil, io.EOF
		})
		defer restore()

		err, _ := GetVaultToken("stub://vault.example/auth", "myrole", "myjwt", nil)
		if err == nil {
			t.Fatal("expected transport error")
		}
	})

	t.Run("invalid json response", func(t *testing.T) {
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{`), nil
		})
		defer restore()

		err, _ := GetVaultToken("stub://vault.example/auth", "myrole", "myjwt", nil)
		if err == nil {
			t.Fatal("expected invalid JSON response")
		}
	})
}

func TestSendVaultCSR(t *testing.T) {
	restoreOriginalIssuerRef := DEFAULT_SIGNER_VAULT_ISSUER_REF
	restoreOriginalTTL := DEFAULT_SIGNER_VAULT_TTL
	DEFAULT_SIGNER_VAULT_ISSUER_REF = "myissuer"
	DEFAULT_SIGNER_VAULT_TTL = "2h"
	t.Cleanup(func() {
		DEFAULT_SIGNER_VAULT_ISSUER_REF = restoreOriginalIssuerRef
		DEFAULT_SIGNER_VAULT_TTL = restoreOriginalTTL
	})

	headers := map[string][]string{
		"X-Vault-Token": {"vault-token"},
	}

	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("X-Vault-Token"); got != "vault-token" {
			t.Fatalf("expected X-Vault-Token header, got %q", got)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		var payload struct {
			CSR        string `json:"csr"`
			CommonName string `json:"common_name"`
			IssuerRef  string `json:"issuer_ref"`
			TTL        string `json:"ttl"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to unmarshal request body: %v", err)
		}
		if payload.CSR != "csr-data" {
			t.Fatalf("expected CSR payload, got %q", payload.CSR)
		}
		if payload.CommonName != "myuser" {
			t.Fatalf("expected common_name 'myuser', got %q", payload.CommonName)
		}
		if payload.IssuerRef != "myissuer" {
			t.Fatalf("expected issuer_ref 'myissuer', got %q", payload.IssuerRef)
		}
		if payload.TTL != "2h" {
			t.Fatalf("expected ttl '2h', got %q", payload.TTL)
		}

		return jsonResponse(http.StatusOK, `{"data":{"certificate":"vault-cert"}}`), nil
	})
	defer restore()

	err, cert := SendVaultCSR("myuser", "stub://vault.example/sign", "csr-data", &headers)
	if err != nil {
		t.Fatalf("SendVaultCSR returned error: %v", err)
	}
	if cert != "vault-cert" {
		t.Fatalf("expected certificate, got %q", cert)
	}
}

func TestSendVaultCSRHandlesErrorResponse(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, `{"errors":["invalid csr"]}`), nil
	})
	defer restore()

	err, cert := SendVaultCSR("myuser", "stub://vault.example/sign", "csr-data", nil)
	if err == nil {
		t.Fatal("expected SendVaultCSR to return an error")
	}
	if cert != "" {
		t.Fatalf("expected no certificate on error, got %q", cert)
	}
}

func TestSendVaultCSRAdditionalErrors(t *testing.T) {
	t.Run("invalid request url", func(t *testing.T) {
		err, _ := SendVaultCSR("myuser", "://bad-url", "csr-data", nil)
		if err == nil {
			t.Fatal("expected invalid URL to return an error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return nil, io.EOF
		})
		defer restore()

		err, _ := SendVaultCSR("myuser", "stub://vault.example/sign", "csr-data", nil)
		if err == nil {
			t.Fatal("expected transport error")
		}
	})

	t.Run("invalid json response", func(t *testing.T) {
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{`), nil
		})
		defer restore()

		err, _ := SendVaultCSR("myuser", "stub://vault.example/sign", "csr-data", nil)
		if err == nil {
			t.Fatal("expected invalid JSON response")
		}
	})
}

func TestGetVaultRootCAAllowsUnauthorizedDuringTest(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusUnauthorized, ""), nil
	})
	defer restore()

	err, cert := GetVaultRootCA(true, "stub://vault.example/ca", nil)
	if err != nil {
		t.Fatalf("GetVaultRootCA returned error: %v", err)
	}
	if cert != "" {
		t.Fatalf("expected empty certificate, got %q", cert)
	}
}

func TestGetVaultRootCAParsesCACertificate(t *testing.T) {
	certBody := `{"data":{"ca_chain":"vault-ca-chain"}}`
	t.Run("ca chain", func(t *testing.T) {
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, certBody), nil
		})
		defer restore()

		err, cert := GetVaultRootCA(false, "stub://vault.example/ca", nil)
		if err != nil {
			t.Fatalf("GetVaultRootCA returned error: %v", err)
		}
		if cert != "vault-ca-chain" {
			t.Fatalf("expected ca_chain, got %q", cert)
		}
	})

	t.Run("with headers", func(t *testing.T) {
		headers := map[string][]string{
			"X-Vault-Token": {"vault-token"},
		}
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			if got := r.Header.Get("X-Vault-Token"); got != "vault-token" {
				t.Fatalf("expected X-Vault-Token header, got %q", got)
			}
			return jsonResponse(http.StatusOK, certBody), nil
		})
		defer restore()

		err, cert := GetVaultRootCA(false, "stub://vault.example/ca", &headers)
		if err != nil {
			t.Fatalf("GetVaultRootCA returned error: %v", err)
		}
		if cert != "vault-ca-chain" {
			t.Fatalf("expected ca_chain, got %q", cert)
		}
	})
}

func TestGetVaultRootCAHandlesErrorResponse(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadGateway, `{"errors":["unavailable"]}`), nil
	})
	defer restore()

	err, cert := GetVaultRootCA(false, "stub://vault.example/ca", nil)
	if err == nil {
		t.Fatal("expected GetVaultRootCA to return an error")
	}
	if cert != "" {
		t.Fatalf("expected no certificate on error, got %q", cert)
	}
}

func TestGetVaultRootCAAdditionalErrors(t *testing.T) {
	t.Run("invalid request url", func(t *testing.T) {
		err, _ := GetVaultRootCA(false, "://bad-url", nil)
		if err == nil {
			t.Fatal("expected invalid URL to return an error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return nil, io.EOF
		})
		defer restore()

		err, _ := GetVaultRootCA(false, "stub://vault.example/ca", nil)
		if err == nil {
			t.Fatal("expected transport error")
		}
	})

	t.Run("invalid json response", func(t *testing.T) {
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{`), nil
		})
		defer restore()

		err, _ := GetVaultRootCA(false, "stub://vault.example/ca", nil)
		if err == nil {
			t.Fatal("expected invalid JSON response")
		}
	})
}
