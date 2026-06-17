package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ctyano/athenz-user-cert/pkg/certificate"
	"github.com/ctyano/athenz-user-cert/pkg/oidc"
	"github.com/ctyano/athenz-user-cert/pkg/signer"
	"gopkg.in/yaml.v3"
)

const (
	envConfigPath     = "ATHENZ_CONFIG_PATH"
	defaultConfigPath = ".athenz/config.yaml"
)

type Settings struct {
	ConfigPath       string
	SignerName       string
	Endpoint         string
	CAEndpoint       string
	SignerTLSCAPath  string
	OIDCIssuer       string
	CNMode           string
	UserClaim        string
	UserDomain       string
	ExternalIDClaim  string
	ExternalIDDomain string
	ResponseMode     string
}

func Load() (*Settings, error) {
	configPath, err := resolveConfigPath()
	if err != nil {
		return nil, err
	}
	values, err := readConfig(configPath)
	if err != nil {
		return nil, err
	}

	applyPackageDefaults(values)

	userClaim := stringValue(values, userClaimKeys(), "ATHENZ_OIDC_USERNAME_CLAIM", "ATHENZ_USERNAME_CLAIM")
	externalIDClaim := stringValue(values, externalIDClaimKeys(), "ATHENZ_EXTERNAL_ID_CLAIM", "ATHENZ_OIDC_EXTERNAL_ID_CLAIM")

	return &Settings{
		ConfigPath:       configPath,
		SignerName:       stringValue(values, []string{"signer.name", "signer"}, "ATHENZ_SIGNER"),
		Endpoint:         stringValue(values, []string{"endpoint", "api_url", "api-url", "signer.endpoint"}, "ATHENZ_API_URL", "ATHENZ_ENDPOINT"),
		CAEndpoint:       stringValue(values, []string{"ca_endpoint", "ca-endpoint", "signer.ca_endpoint", "signer.ca-endpoint"}, "ATHENZ_CA_ENDPOINT"),
		SignerTLSCAPath:  stringValue(values, []string{"signer_tls_ca_path", "signer-tls-ca-path", "signer.tls_ca_path", "signer.tls-ca-path"}, "ATHENZ_SIGNER_TLS_CA_PATH"),
		OIDCIssuer:       stringValue(values, []string{"oidc.issuer", "issuer"}, "ATHENZ_OIDC_ISSUER", "ATHENZ_ISSUER"),
		CNMode:           stringValue(values, cnModeKeys(), "ATHENZ_CN_MODE"),
		UserClaim:        userClaim,
		UserDomain:       stringValue(values, userDomainKeys(), "ATHENZ_USER_DOMAIN"),
		ExternalIDClaim:  externalIDClaim,
		ExternalIDDomain: stringValue(values, externalIDDomainKeys(), "ATHENZ_EXTERNAL_ID_DOMAIN"),
		ResponseMode:     stringValue(values, []string{"oidc.response_mode", "oidc.response-mode", "response_mode", "response-mode"}, "ATHENZ_OIDC_RESPONSE_MODE", "ATHENZ_RESPONSE_MODE"),
	}, nil
}

func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, defaultConfigPath), nil
}

func resolveConfigPath() (string, error) {
	if path := strings.TrimSpace(os.Getenv(envConfigPath)); path != "" {
		return expandHome(path), nil
	}
	path, err := DefaultConfigPath()
	if err != nil {
		return "", fmt.Errorf("failed to resolve default config path: %w", err)
	}
	return path, nil
}

func readConfig(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && strings.TrimSpace(os.Getenv(envConfigPath)) == "" {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	values := map[string]any{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}
	return values, nil
}

func applyPackageDefaults(values map[string]any) {
	setString(values, &oidc.DEFAULT_OIDC_CLIENT_ID, []string{"oidc.client_id", "oidc.client-id", "client_id", "client-id"}, "ATHENZ_OIDC_CLIENT_ID", "ATHENZ_CLIENT_ID")
	setString(values, &oidc.DEFAULT_OIDC_CLIENT_SECRET, []string{"oidc.client_secret", "oidc.client-secret", "client_secret", "client-secret"}, "ATHENZ_OIDC_CLIENT_SECRET", "ATHENZ_CLIENT_SECRET")
	setString(values, &oidc.DEFAULT_OIDC_ISSUER, []string{"oidc.issuer", "issuer"}, "ATHENZ_OIDC_ISSUER", "ATHENZ_ISSUER")
	setString(values, &oidc.DEFAULT_OIDC_SCOPES, []string{"oidc.scopes", "scopes"}, "ATHENZ_OIDC_SCOPES")
	setString(values, &oidc.DEFAULT_OIDC_LISTEN_ADDRESS, []string{"oidc.listen_address", "oidc.listen-address", "listen_address", "listen-address"}, "ATHENZ_OIDC_LISTEN_ADDRESS")
	setString(values, &oidc.DEFAULT_OIDC_ACCESS_TOKEN_PATH, []string{"oidc.access_token_path", "oidc.access-token-path", "access_token_path", "access-token-path"}, "ATHENZ_OIDC_ACCESS_TOKEN_PATH")
	setString(values, &oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM, userClaimKeys(), "ATHENZ_OIDC_USERNAME_CLAIM", "ATHENZ_USERNAME_CLAIM")
	setString(values, &oidc.DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM, externalIDClaimKeys(), "ATHENZ_EXTERNAL_ID_CLAIM", "ATHENZ_OIDC_EXTERNAL_ID_CLAIM")

	setString(values, &certificate.DEFAULT_ATHENZ_CN_MODE, cnModeKeys(), "ATHENZ_CN_MODE")
	setString(values, &certificate.DEFAULT_ATHENZ_USER_DOMAIN, userDomainKeys(), "ATHENZ_USER_DOMAIN")
	setString(values, &certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN, externalIDDomainKeys(), "ATHENZ_EXTERNAL_ID_DOMAIN")

	setString(values, &signer.DEFAULT_SIGNER_TLS_CA_PATH, []string{"signer_tls_ca_path", "signer-tls-ca-path", "signer.tls_ca_path", "signer.tls-ca-path"}, "ATHENZ_SIGNER_TLS_CA_PATH")

	setString(values, &signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL, []string{"crypki.sign_url", "crypki.sign-url", "signer.crypki.sign_url", "signer.crypki.sign-url"}, "ATHENZ_CRYPKI_SIGN_URL")
	setString(values, &signer.DEFAULT_SIGNER_CRYPKI_CA_URL, []string{"crypki.ca_endpoint", "crypki.ca-endpoint", "signer.crypki.ca_endpoint", "signer.crypki.ca-endpoint"}, "ATHENZ_CRYPKI_CA_ENDPOINT")
	setString(values, &signer.DEFAULT_SIGNER_CRYPKI_VALIDITY, []string{"crypki.validity", "signer.crypki.validity"}, "ATHENZ_CRYPKI_VALIDITY")
	setString(values, &signer.DEFAULT_SIGNER_CRYPKI_IDENTIFIER, []string{"crypki.identifier", "signer.crypki.identifier"}, "ATHENZ_CRYPKI_IDENTIFIER")
	setString(values, &signer.DEFAULT_SIGNER_CRYPKI_TIMEOUT, []string{"crypki.timeout", "signer.crypki.timeout"}, "ATHENZ_CRYPKI_TIMEOUT")

	setString(values, &signer.DEFAULT_SIGNER_CFSSL_SIGN_URL, []string{"cfssl.sign_url", "cfssl.sign-url", "signer.cfssl.sign_url", "signer.cfssl.sign-url"}, "ATHENZ_CFSSL_SIGN_URL")
	setString(values, &signer.DEFAULT_SIGNER_CFSSL_CA_URL, []string{"cfssl.ca_endpoint", "cfssl.ca-endpoint", "signer.cfssl.ca_endpoint", "signer.cfssl.ca-endpoint"}, "ATHENZ_CFSSL_CA_ENDPOINT")
	setString(values, &signer.DEFAULT_SIGNER_CFSSL_TIMEOUT, []string{"cfssl.timeout", "signer.cfssl.timeout"}, "ATHENZ_CFSSL_TIMEOUT")

	setString(values, &signer.DEFAULT_SIGNER_ZTS_SIGN_URL, []string{"zts.sign_url", "zts.sign-url", "signer.zts.sign_url", "signer.zts.sign-url"}, "ATHENZ_ZTS_SIGN_URL")
	setString(values, &signer.DEFAULT_SIGNER_ZTS_CA_URL, []string{"zts.ca_endpoint", "zts.ca-endpoint", "signer.zts.ca_endpoint", "signer.zts.ca-endpoint"}, "ATHENZ_ZTS_CA_ENDPOINT")
	setString(values, &signer.DEFAULT_SIGNER_ZTS_TIMEOUT, []string{"zts.timeout", "signer.zts.timeout"}, "ATHENZ_ZTS_TIMEOUT")
}

func cnModeKeys() []string {
	return []string{
		"athenz.cn_mode",
		"athenz.cn-mode",
		"cn_mode",
		"cn-mode",
	}
}

func externalIDDomainKeys() []string {
	return []string{
		"athenz.external_id_domain",
		"athenz.external-id-domain",
		"external_id_domain",
		"external-id-domain",
	}
}

func userDomainKeys() []string {
	return []string{
		"athenz.user_domain",
		"athenz.user-domain",
		"user_domain",
		"user-domain",
	}
}

func userClaimKeys() []string {
	return []string{
		"athenz.user_claim",
		"athenz.user-claim",
		"oidc.username_claim",
		"oidc.username-claim",
		"username_claim",
		"username-claim",
		"claim",
	}
}

func externalIDClaimKeys() []string {
	return []string{
		"athenz.external_id_claim",
		"athenz.external-id-claim",
		"oidc.external_id_claim",
		"oidc.external-id-claim",
		"external_id_claim",
		"external-id-claim",
		"claim",
	}
}

func setString(values map[string]any, target *string, keys []string, envs ...string) {
	if value := stringValue(values, keys, envs...); value != "" {
		*target = value
	}
}

func stringValue(values map[string]any, keys []string, envs ...string) string {
	if value := envValue(envs...); value != "" {
		return expandHome(value)
	}
	return configValue(values, keys...)
}

func envValue(envs ...string) string {
	for _, env := range envs {
		if value := strings.TrimSpace(os.Getenv(env)); value != "" {
			return value
		}
	}
	return ""
}

func configValue(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := valueAtPath(values, key); value != "" {
			return expandHome(value)
		}
	}
	return ""
}

func valueAtPath(values map[string]any, key string) string {
	var current any = values
	for _, part := range strings.Split(key, ".") {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = m[part]
		if !ok {
			return ""
		}
	}
	switch current.(type) {
	case nil, map[string]any, []any:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(current))
	}
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}
