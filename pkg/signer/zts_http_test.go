package signer

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSendZTSCSR(t *testing.T) {
	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("expected Authorization header, got %q", got)
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
			t.Fatalf("expected json content type, got %q", got)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		var payload ztsUserCertificateRequest
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to parse request body: %v", err)
		}
		if payload.Name != "athenz.user" {
			t.Fatalf("expected request name, got %q", payload.Name)
		}
		if payload.CSR != "csr-data" {
			t.Fatalf("expected request csr, got %q", payload.CSR)
		}
		if payload.AttestationData != "code=test-code" {
			t.Fatalf("expected request attestation data, got %q", payload.AttestationData)
		}

		return jsonResponse(http.StatusOK, `{"x509Certificate":"signed-cert"}`), nil
	})
	defer restore()

	headers := map[string][]string{
		"Authorization": {"Bearer token"},
	}

	err, cert := SendZTSCSR("athenz.user", "https://zts.example/usercert", "csr-data", "code=test-code", "", &headers)
	if err != nil {
		t.Fatalf("SendZTSCSR returned error: %v", err)
	}
	if cert != "signed-cert" {
		t.Fatalf("expected certificate, got %q", cert)
	}
}

func TestSendZTSExternalIDCSR(t *testing.T) {
	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/zts/v1/extmembercert" {
			t.Fatalf("expected external ID certificate path, got %q", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
			t.Fatalf("expected json content type, got %q", got)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		var payload ztsExternalMemberCertificateRequest
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to parse request body: %v", err)
		}
		if payload.Name != "email:ext.joe@athenz.io" {
			t.Fatalf("expected external ID name, got %q", payload.Name)
		}
		if payload.CSR != "csr-data" {
			t.Fatalf("expected request csr, got %q", payload.CSR)
		}
		if payload.AttestationData != "code=test-code" {
			t.Fatalf("expected request attestation data, got %q", payload.AttestationData)
		}

		return jsonResponse(http.StatusOK, `{"x509Certificate":"external-id-cert"}`), nil
	})
	defer restore()

	err, cert := SendZTSExternalIDCSR("email:ext.joe@athenz.io", "https://zts.example/zts/v1/extmembercert", "csr-data", "code=test-code", "", nil)
	if err != nil {
		t.Fatalf("SendZTSExternalIDCSR returned error: %v", err)
	}
	if cert != "external-id-cert" {
		t.Fatalf("expected certificate, got %q", cert)
	}
}

func TestSendZTSCSRHandlesErrorResponse(t *testing.T) {
	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, `{"error":"bad csr"}`), nil
	})
	defer restore()

	err, cert := SendZTSCSR("athenz.user", "https://zts.example/usercert", "csr-data", "code=test-code", "", nil)
	if err == nil {
		t.Fatal("expected SendZTSCSR to return an error")
	}
	if cert != "" {
		t.Fatalf("expected no certificate on error, got %q", cert)
	}
	if !strings.Contains(err.Error(), "Received non-OK status") {
		t.Fatalf("expected HTTP status error, got %v", err)
	}
}

func TestSendZTSCSRAdditionalErrors(t *testing.T) {
	t.Run("invalid request url", func(t *testing.T) {
		if err, _ := SendZTSCSR("athenz.user", "://bad-url", "csr-data", "code=test-code", "", nil); err == nil {
			t.Fatal("expected invalid URL to return an error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
		DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
		t.Cleanup(func() {
			DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
		})

		restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return nil, io.EOF
		})
		defer restore()

		if err, _ := SendZTSCSR("athenz.user", "https://zts.example/usercert", "csr-data", "code=test-code", "", nil); err == nil {
			t.Fatal("expected transport error")
		}
	})

	t.Run("unknown authority transport error", func(t *testing.T) {
		originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
		DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
		t.Cleanup(func() {
			DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
		})

		restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("x509: certificate signed by unknown authority")
		})
		defer restore()

		if err, _ := SendZTSCSR("athenz.user", "https://zts.example/usercert", "csr-data", "code=test-code", "", nil); err == nil || !strings.Contains(err.Error(), "set -signer-tls-ca") {
			t.Fatalf("expected unknown authority hint, got %v", err)
		}
	})

	t.Run("invalid json response", func(t *testing.T) {
		originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
		DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
		t.Cleanup(func() {
			DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
		})

		restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{`), nil
		})
		defer restore()

		if err, _ := SendZTSCSR("athenz.user", "https://zts.example/usercert", "csr-data", "code=test-code", "", nil); err == nil {
			t.Fatal("expected invalid JSON response")
		}
	})

	t.Run("missing certificate response", func(t *testing.T) {
		originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
		DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
		t.Cleanup(func() {
			DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
		})

		restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{}`), nil
		})
		defer restore()

		if err, _ := SendZTSCSR("athenz.user", "https://zts.example/usercert", "csr-data", "code=test-code", "", nil); err == nil || !strings.Contains(err.Error(), "x509Certificate is missing") {
			t.Fatalf("expected missing x509Certificate error, got %v", err)
		}
	})
}

func TestGetZTSRootCAFetchesRemoteBundle(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		return jsonResponse(http.StatusOK, `{"caCertificates":"remote-ca"}`), nil
	})
	defer restore()

	err, cert := GetZTSRootCA(false, "https://zts.example/ca", nil)
	if err != nil {
		t.Fatalf("GetZTSRootCA returned error: %v", err)
	}
	if cert != "remote-ca" {
		t.Fatalf("expected remote CA bundle, got %q", cert)
	}
}

func TestGetZTSRootCAHandlesErrorResponse(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusInternalServerError, `{"error":"missing bundle"}`), nil
	})
	defer restore()

	err, cert := GetZTSRootCA(false, "https://zts.example/ca", nil)
	if err == nil {
		t.Fatal("expected GetZTSRootCA to return an error")
	}
	if cert != "" {
		t.Fatalf("expected empty certificate on error, got %q", cert)
	}
	if !strings.Contains(err.Error(), "Received non-OK status") {
		t.Fatalf("expected HTTP status error, got %v", err)
	}
}

func TestGetZTSRootCAAdditionalPaths(t *testing.T) {
	t.Run("empty source", func(t *testing.T) {
		if err, cert := GetZTSRootCA(false, "", nil); err != nil || cert != "" {
			t.Fatalf("expected empty source to return empty bundle, cert=%q err=%v", cert, err)
		}
	})

	t.Run("read response body error", func(t *testing.T) {
		originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
		DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
		t.Cleanup(func() {
			DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
		})

		restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     http.StatusText(http.StatusOK),
				Header:     make(http.Header),
				Body:       io.NopCloser(errReader{}),
				Request:    &http.Request{URL: r.URL},
				ProtoMajor: 1,
				ProtoMinor: 1,
			}, nil
		})
		defer restore()

		if err, _ := GetZTSRootCA(false, "https://zts.example/ca", nil); err == nil {
			t.Fatal("expected response body read error")
		}
	})

	t.Run("invalid request url", func(t *testing.T) {
		if err, _ := GetZTSRootCA(false, "://bad-url", nil); err == nil {
			t.Fatal("expected invalid URL to return an error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
		DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
		t.Cleanup(func() {
			DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
		})

		restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return nil, io.EOF
		})
		defer restore()

		if err, _ := GetZTSRootCA(false, "https://zts.example/ca", nil); err == nil {
			t.Fatal("expected transport error")
		}
	})
}

func TestSignerHTTPClientSignerTLSCAPathErrors(t *testing.T) {
	t.Run("empty local file", func(t *testing.T) {
		caPath := filepath.Join(t.TempDir(), "empty-ca.pem")
		if err := os.WriteFile(caPath, nil, 0600); err != nil {
			t.Fatalf("failed to write empty CA file: %v", err)
		}
		client, err := newSignerHTTPClient("10", caPath)
		if err != nil {
			t.Fatalf("expected empty signer TLS CA to be ignored, got %v", err)
		}
		if client == nil {
			t.Fatal("expected http client")
		}
	})

	t.Run("missing custom local file", func(t *testing.T) {
		if _, err := newSignerHTTPClient("10", filepath.Join(t.TempDir(), "missing-ca.pem")); err == nil {
			t.Fatal("expected missing signer TLS CA file to return an error")
		}
	})

	t.Run("invalid CA bundle", func(t *testing.T) {
		caPath := filepath.Join(t.TempDir(), "invalid-ca.pem")
		if err := os.WriteFile(caPath, []byte("not-a-cert"), 0600); err != nil {
			t.Fatalf("failed to write invalid CA file: %v", err)
		}
		if _, err := newSignerHTTPClient("10", caPath); err == nil {
			t.Fatal("expected invalid signer TLS CA bundle to return an error")
		}
	})
}

func TestParseZTSRootCAResponseAdditionalVariants(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr string
	}{
		{
			name: "x509 certificate signer",
			body: `{"x509CertificateSigner":"signer-ca"}`,
			want: "signer-ca",
		},
		{
			name: "ca certificates",
			body: `{"caCertificates":"ca-certificates"}`,
			want: "ca-certificates",
		},
		{
			name: "certificate",
			body: `{"certificate":"certificate-field"}`,
			want: "certificate-field",
		},
		{
			name: "cert",
			body: `{"cert":"cert-field"}`,
			want: "cert-field",
		},
		{
			name:    "invalid json",
			body:    `not-json`,
			wantErr: "Failed to parse JSON response",
		},
		{
			name:    "missing bundle",
			body:    `{}`,
			wantErr: "No CA certificate bundle found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseZTSRootCAResponse([]byte(tt.body), "https://zts.example/ca", false)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseZTSRootCAResponse returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func stubZTSDefaultTransport(t *testing.T, roundTrip func(*http.Request) (*http.Response, error)) func() {
	t.Helper()

	original := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(roundTrip)
	return func() {
		http.DefaultTransport = original
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, io.EOF
}
