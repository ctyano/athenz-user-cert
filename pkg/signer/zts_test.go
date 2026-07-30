package signer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGetZTSRootCAParsesCertificateAuthorityBundleCerts(t *testing.T) {
	want := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	body, err := json.Marshal(map[string]string{
		"name":  "athenz",
		"certs": want,
	})
	if err != nil {
		t.Fatalf("failed to marshal response body: %v", err)
	}

	got, err := parseZTSRootCAResponse(body, "https://zts.example/ca", false)
	if err != nil {
		t.Fatalf("parseZTSRootCAResponse returned error: %v", err)
	}
	if got != want {
		t.Fatalf("expected CA bundle from certs field, got %q", got)
	}
}

func TestGetZTSRootCAParsesCACertBundle(t *testing.T) {
	want := "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----"
	body, err := json.Marshal(map[string]string{
		"caCertBundle": want,
	})
	if err != nil {
		t.Fatalf("failed to marshal response body: %v", err)
	}

	got, err := parseZTSRootCAResponse(body, "https://zts.example/ca", false)
	if err != nil {
		t.Fatalf("parseZTSRootCAResponse returned error: %v", err)
	}
	if got != want {
		t.Fatalf("expected CA bundle from caCertBundle field, got %q", got)
	}
}

func TestNewSignerHTTPClientAllowsEmptySignerTLSCAPath(t *testing.T) {
	client, err := newSignerHTTPClient("10", "")
	if err != nil {
		t.Fatalf("newSignerHTTPClient returned error: %v", err)
	}
	if client == nil {
		t.Fatal("expected http client")
	}
}

func TestNewSignerHTTPClientRejectsRemoteSignerTLSCAPath(t *testing.T) {
	if _, err := newSignerHTTPClient("10", "https://zts.example/ca"); err == nil {
		t.Fatal("expected remote signer TLS CA to return an error")
	}
}

func TestDefaultSignerTLSCAPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	originalDefault := DEFAULT_SIGNER_TLS_CA_PATH
	t.Cleanup(func() {
		DEFAULT_SIGNER_TLS_CA_PATH = originalDefault
	})

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: "", want: ""},
		{name: "absolute", path: "/tmp/ca.pem", want: "/tmp/ca.pem"},
		{name: "remote", path: "https://zts.example/ca.pem", want: "https://zts.example/ca.pem"},
		{name: "relative", path: ".athenz/ca.cert.pem", want: filepath.Join(home, ".athenz/ca.cert.pem")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DEFAULT_SIGNER_TLS_CA_PATH = tt.path
			if got := DefaultSignerTLSCAPath(); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestDefaultZTSCertificateEndpoints(t *testing.T) {
	originalSignURL := DEFAULT_SIGNER_ZTS_SIGN_URL
	originalExternalMemberCertEndpoint := DEFAULT_SIGNER_ZTS_EXTERNAL_MEMBER_CERT_ENDPOINT
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_SIGN_URL = originalSignURL
		DEFAULT_SIGNER_ZTS_EXTERNAL_MEMBER_CERT_ENDPOINT = originalExternalMemberCertEndpoint
	})

	DEFAULT_SIGNER_ZTS_SIGN_URL = "https://zts.example/zts/v1"
	DEFAULT_SIGNER_ZTS_EXTERNAL_MEMBER_CERT_ENDPOINT = ""

	if got := DefaultZTSUserCertificateEndpoint(); got != "https://zts.example/zts/v1/usercert" {
		t.Fatalf("expected user certificate endpoint, got %q", got)
	}
	if got := DefaultZTSExternalMemberCertEndpoint(); got != "https://zts.example/zts/v1/extmembercert" {
		t.Fatalf("expected external member certificate endpoint, got %q", got)
	}

	DEFAULT_SIGNER_ZTS_SIGN_URL = "https://zts.example/zts/v1/"
	if got := DefaultZTSUserCertificateEndpoint(); got != "https://zts.example/zts/v1/usercert" {
		t.Fatalf("expected normalized user certificate endpoint, got %q", got)
	}
	if got := DefaultZTSExternalMemberCertEndpoint(); got != "https://zts.example/zts/v1/extmembercert" {
		t.Fatalf("expected normalized external member certificate endpoint, got %q", got)
	}

	DEFAULT_SIGNER_ZTS_SIGN_URL = "https://zts.example/zts/v1/usercert"
	if got := DefaultZTSUserCertificateEndpoint(); got != "https://zts.example/zts/v1/usercert" {
		t.Fatalf("expected legacy user certificate endpoint to be preserved, got %q", got)
	}
	if got := DefaultZTSExternalMemberCertEndpoint(); got != "https://zts.example/zts/v1/extmembercert" {
		t.Fatalf("expected external member certificate endpoint from legacy sign URL, got %q", got)
	}

	DEFAULT_SIGNER_ZTS_EXTERNAL_MEMBER_CERT_ENDPOINT = "https://zts-alt.example/zts/v1/extmembercert"
	if got := DefaultZTSExternalMemberCertEndpoint(); got != "https://zts-alt.example/zts/v1/extmembercert" {
		t.Fatalf("expected explicit external member certificate endpoint, got %q", got)
	}
}

func TestNewSignerHTTPClientUsesExplicitRelativePathAsIs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if err := os.WriteFile(filepath.Join(home, "relative-ca.pem"), []byte(createSelfSignedCertPEM(t)), 0600); err != nil {
		t.Fatalf("failed to write home CA file: %v", err)
	}
	if _, err := newSignerHTTPClient("10", "relative-ca.pem"); err == nil {
		t.Fatal("expected explicit relative path to be read as-is")
	}
}
