package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ctyano/athenz-user-cert/pkg/certificate"
	"github.com/ctyano/athenz-user-cert/pkg/oidc"
	"github.com/ctyano/athenz-user-cert/pkg/signer"
)

func TestLoadAppliesConfigAndEnvOverrides(t *testing.T) {
	restore := saveDefaults()
	defer restore()

	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	caPath := filepath.Join(home, "ca.pem")
	if err := os.WriteFile(configPath, []byte(`
signer:
  name: zts
endpoint: https://config.example/zts/v1/usercert
ca_endpoint: https://config.example/zts/v1/ca
signer_tls_ca_path: ~/ca.pem
athenz:
  cn_mode: external
  user_domain: config.user.domain
  external_id_domain: config.external.domain
oidc:
  issuer: https://issuer.config.example
  username_claim: name
  external_id_claim: email
zts:
  sign_url: https://zts.config.example/zts/v1/usercert
  ca_endpoint: https://zts.config.example/zts/v1/ca
`), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv(envConfigPath, configPath)
	t.Setenv("HOME", home)
	t.Setenv("ATHENZ_API_URL", "https://env.example/zts/v1/usercert")
	t.Setenv("ATHENZ_CA_ENDPOINT", "https://env.example/zts/v1/ca")
	t.Setenv("ATHENZ_ZTS_SIGN_URL", "https://zts.env.example/zts/v1/usercert")

	settings, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if settings.SignerName != "zts" {
		t.Fatalf("expected signer name from config, got %q", settings.SignerName)
	}
	if settings.Endpoint != "https://env.example/zts/v1/usercert" {
		t.Fatalf("expected endpoint from env, got %q", settings.Endpoint)
	}
	if settings.CAEndpoint != "https://env.example/zts/v1/ca" {
		t.Fatalf("expected CA endpoint from env, got %q", settings.CAEndpoint)
	}
	if settings.SignerTLSCAPath != caPath {
		t.Fatalf("expected expanded signer TLS CA path %q, got %q", caPath, settings.SignerTLSCAPath)
	}
	if settings.OIDCIssuer != "https://issuer.config.example" {
		t.Fatalf("expected oidc issuer from config, got %q", settings.OIDCIssuer)
	}
	if settings.CNMode != "external" {
		t.Fatalf("expected CN mode from config, got %q", settings.CNMode)
	}
	if settings.UserClaim != "name" {
		t.Fatalf("expected user claim from config, got %q", settings.UserClaim)
	}
	if settings.UserDomain != "config.user.domain" {
		t.Fatalf("expected Athenz user domain from config, got %q", settings.UserDomain)
	}
	if settings.ExternalIDClaim != "email" {
		t.Fatalf("expected external ID claim from config, got %q", settings.ExternalIDClaim)
	}
	if settings.ExternalIDDomain != "config.external.domain" {
		t.Fatalf("expected Athenz external ID domain from config, got %q", settings.ExternalIDDomain)
	}
	if oidc.DEFAULT_OIDC_ISSUER != "https://issuer.config.example" {
		t.Fatalf("expected oidc issuer from config, got %q", oidc.DEFAULT_OIDC_ISSUER)
	}
	if oidc.DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM != "email" {
		t.Fatalf("expected external ID claim default from config, got %q", oidc.DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM)
	}
	if oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM != "name" {
		t.Fatalf("expected user claim default from config, got %q", oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM)
	}
	if certificate.DEFAULT_ATHENZ_CN_MODE != "external" {
		t.Fatalf("expected Athenz CN mode default from config, got %q", certificate.DEFAULT_ATHENZ_CN_MODE)
	}
	if certificate.DEFAULT_ATHENZ_USER_DOMAIN != "config.user.domain" {
		t.Fatalf("expected Athenz user domain default from config, got %q", certificate.DEFAULT_ATHENZ_USER_DOMAIN)
	}
	if certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN != "config.external.domain" {
		t.Fatalf("expected Athenz external ID domain default from config, got %q", certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN)
	}
	if signer.DEFAULT_SIGNER_ZTS_SIGN_URL != "https://zts.env.example/zts/v1/usercert" {
		t.Fatalf("expected zts sign url from env, got %q", signer.DEFAULT_SIGNER_ZTS_SIGN_URL)
	}
}

func TestLoadIgnoresMissingDefaultConfig(t *testing.T) {
	restore := saveDefaults()
	defer restore()

	t.Setenv("HOME", t.TempDir())
	t.Setenv(envConfigPath, "")

	if _, err := Load(); err != nil {
		t.Fatalf("expected missing default config to be ignored, got %v", err)
	}
}

func TestLoadDoesNotTreatNestedSignerMapAsSignerName(t *testing.T) {
	restore := saveDefaults()
	defer restore()

	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`
signer:
  endpoint: https://config.example/zts/v1/usercert
`), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv(envConfigPath, configPath)

	settings, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if settings.SignerName != "" {
		t.Fatalf("expected empty signer name, got %q", settings.SignerName)
	}
	if settings.Endpoint != "https://config.example/zts/v1/usercert" {
		t.Fatalf("expected signer endpoint, got %q", settings.Endpoint)
	}
}

func TestLoadErrorsWhenExplicitConfigIsMissing(t *testing.T) {
	restore := saveDefaults()
	defer restore()

	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing.yaml"))

	if _, err := Load(); err == nil {
		t.Fatal("expected missing explicit config to return an error")
	}
}

func TestDefaultConfigPathAndExpandHome(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	got, err := DefaultConfigPath()
	if err != nil {
		t.Fatalf("DefaultConfigPath returned error: %v", err)
	}
	if want := filepath.Join(os.Getenv("HOME"), defaultConfigPath); got != want {
		t.Fatalf("expected default config path %q, got %q", want, got)
	}
	if got := expandHome("~/nested/config.yaml"); got != filepath.Join(os.Getenv("HOME"), "nested/config.yaml") {
		t.Fatalf("expected expanded home path, got %q", got)
	}
	if got := expandHome("plain/path.yaml"); got != "plain/path.yaml" {
		t.Fatalf("expected plain path to remain unchanged, got %q", got)
	}
}

func TestReadConfigRejectsInvalidYAML(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("signer: ["), 0600); err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}

	if _, err := readConfig(configPath); err == nil {
		t.Fatal("expected invalid yaml to return an error")
	}
}

func saveDefaults() func() {
	oidcClientID := oidc.DEFAULT_OIDC_CLIENT_ID
	oidcClientSecret := oidc.DEFAULT_OIDC_CLIENT_SECRET
	oidcIssuer := oidc.DEFAULT_OIDC_ISSUER
	oidcScopes := oidc.DEFAULT_OIDC_SCOPES
	oidcListenAddress := oidc.DEFAULT_OIDC_LISTEN_ADDRESS
	oidcAccessTokenPath := oidc.DEFAULT_OIDC_ACCESS_TOKEN_PATH
	oidcExternalIDClaim := oidc.DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM
	oidcUsernameClaim := oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM
	athenzCNMode := certificate.DEFAULT_ATHENZ_CN_MODE
	athenzUserDomain := certificate.DEFAULT_ATHENZ_USER_DOMAIN
	externalIDDomain := certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN

	crypkiSignURL := signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL
	crypkiCAURL := signer.DEFAULT_SIGNER_CRYPKI_CA_URL
	crypkiValidity := signer.DEFAULT_SIGNER_CRYPKI_VALIDITY
	crypkiIdentifier := signer.DEFAULT_SIGNER_CRYPKI_IDENTIFIER
	crypkiTimeout := signer.DEFAULT_SIGNER_CRYPKI_TIMEOUT

	cfsslSignURL := signer.DEFAULT_SIGNER_CFSSL_SIGN_URL
	cfsslCAURL := signer.DEFAULT_SIGNER_CFSSL_CA_URL
	cfsslTimeout := signer.DEFAULT_SIGNER_CFSSL_TIMEOUT

	ztsSignURL := signer.DEFAULT_SIGNER_ZTS_SIGN_URL
	ztsCAURL := signer.DEFAULT_SIGNER_ZTS_CA_URL
	ztsTimeout := signer.DEFAULT_SIGNER_ZTS_TIMEOUT
	signerTLSCAPath := signer.DEFAULT_SIGNER_TLS_CA_PATH

	return func() {
		oidc.DEFAULT_OIDC_CLIENT_ID = oidcClientID
		oidc.DEFAULT_OIDC_CLIENT_SECRET = oidcClientSecret
		oidc.DEFAULT_OIDC_ISSUER = oidcIssuer
		oidc.DEFAULT_OIDC_SCOPES = oidcScopes
		oidc.DEFAULT_OIDC_LISTEN_ADDRESS = oidcListenAddress
		oidc.DEFAULT_OIDC_ACCESS_TOKEN_PATH = oidcAccessTokenPath
		oidc.DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM = oidcExternalIDClaim
		oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM = oidcUsernameClaim
		certificate.DEFAULT_ATHENZ_CN_MODE = athenzCNMode
		certificate.DEFAULT_ATHENZ_USER_DOMAIN = athenzUserDomain
		certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN = externalIDDomain

		signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL = crypkiSignURL
		signer.DEFAULT_SIGNER_CRYPKI_CA_URL = crypkiCAURL
		signer.DEFAULT_SIGNER_CRYPKI_VALIDITY = crypkiValidity
		signer.DEFAULT_SIGNER_CRYPKI_IDENTIFIER = crypkiIdentifier
		signer.DEFAULT_SIGNER_CRYPKI_TIMEOUT = crypkiTimeout

		signer.DEFAULT_SIGNER_CFSSL_SIGN_URL = cfsslSignURL
		signer.DEFAULT_SIGNER_CFSSL_CA_URL = cfsslCAURL
		signer.DEFAULT_SIGNER_CFSSL_TIMEOUT = cfsslTimeout

		signer.DEFAULT_SIGNER_ZTS_SIGN_URL = ztsSignURL
		signer.DEFAULT_SIGNER_ZTS_CA_URL = ztsCAURL
		signer.DEFAULT_SIGNER_ZTS_TIMEOUT = ztsTimeout
		signer.DEFAULT_SIGNER_TLS_CA_PATH = signerTLSCAPath
	}
}
