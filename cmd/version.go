package main

import (
	"flag"
	"fmt"

	"github.com/ctyano/athenz-user-cert/pkg/certificate"
	"github.com/ctyano/athenz-user-cert/pkg/oidc"
	"github.com/ctyano/athenz-user-cert/pkg/signer"
)

var (
	VERSION    = "v0.0.0"
	BUILD_DATE = "1970/01/01"
)

func ExecuteVersionCommand(arg []string, versionFlagSet *flag.FlagSet) {

	// Parse argument flags
	versionFlagSet.Parse(arg)

	fmt.Printf("CLI basic configuration:\n")
	fmt.Printf("  CLI built date: %s\n", BUILD_DATE)
	fmt.Printf("  CLI version: %s\n", VERSION)

	fmt.Printf("CLI Open ID configuration:\n")
	fmt.Printf("  CLI Open ID Connect Issuer: %s\n", oidc.DEFAULT_OIDC_ISSUER)
	fmt.Printf("  CLI Open ID Connect Client ID: %s\n", oidc.DEFAULT_OIDC_CLIENT_ID)
	fmt.Printf("  CLI Open ID Connect Scopes: %s\n", oidc.DEFAULT_OIDC_SCOPES)
	fmt.Printf("  CLI Open ID Connect Client Listening Address: %s\n", oidc.DEFAULT_OIDC_LISTEN_ADDRESS)
	fmt.Printf("  CLI Open ID Connect Access Token Stored Path: $HOME/%s\n", oidc.DEFAULT_OIDC_ACCESS_TOKEN_PATH)
	fmt.Printf("  CLI Open ID Connect Access Token Cache Validation: JWT exp claim\n")
	fmt.Printf("  CLI Open ID Connect Access Token User Name JWT Claim: %s\n", oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM)
	fmt.Printf("  CLI Open ID Connect Access Token External ID JWT Claim: %s\n", oidc.DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM)

	fmt.Printf("CLI X.509 configuration:\n")
	fmt.Printf("  CLI X.509 Athenz CN Mode: %s\n", certificate.DEFAULT_ATHENZ_CN_MODE)
	fmt.Printf("  CLI X.509 Athenz User Domain: %s\n", certificate.DEFAULT_ATHENZ_USER_DOMAIN)
	fmt.Printf("  CLI X.509 Athenz External ID Domain: %s\n", certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN)
	fmt.Printf("  CLI X.509 Signer TLS CA Path: %s\n", signer.DEFAULT_SIGNER_TLS_CA_PATH)
	fmt.Printf("  CLI X.509 configuration for Crypki:\n")
	fmt.Printf("    CLI X.509 Certificate Signer URL: %s\n", signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL)
	fmt.Printf("    CLI X.509 Certificate CA Endpoint: %s\n", signer.DEFAULT_SIGNER_CRYPKI_CA_URL)
	fmt.Printf("    CLI X.509 Certificate Validity: %s seconds\n", signer.DEFAULT_SIGNER_CRYPKI_VALIDITY)
	fmt.Printf("    CLI X.509 Certificate Identifier: %s\n", signer.DEFAULT_SIGNER_CRYPKI_IDENTIFIER)
	fmt.Printf("    CLI X.509 Certificate Request Timeout: %s seconds\n", signer.DEFAULT_SIGNER_CRYPKI_TIMEOUT)
	fmt.Printf("  CLI X.509 configuration for CFSSL:\n")
	fmt.Printf("    CLI X.509 Certificate Signer URL: %s\n", signer.DEFAULT_SIGNER_CFSSL_SIGN_URL)
	fmt.Printf("    CLI X.509 Certificate CA Endpoint: %s\n", signer.DEFAULT_SIGNER_CFSSL_CA_URL)
	fmt.Printf("    CLI X.509 Certificate Request Timeout: %s seconds\n", signer.DEFAULT_SIGNER_CFSSL_TIMEOUT)
	fmt.Printf("  CLI X.509 configuration for ZTS:\n")
	fmt.Printf("    CLI X.509 Certificate Signer URL: %s\n", signer.DEFAULT_SIGNER_ZTS_SIGN_URL)
	fmt.Printf("    CLI X.509 Certificate CA Endpoint: %s\n", signer.DEFAULT_SIGNER_ZTS_CA_URL)
	fmt.Printf("    CLI X.509 Certificate Request Timeout: %s seconds\n", signer.DEFAULT_SIGNER_ZTS_TIMEOUT)
	fmt.Printf("  CLI X.509 configuration for Vault:\n")
	fmt.Printf("    CLI X.509 Certificate Login URL: %s\n", signer.DEFAULT_SIGNER_VAULT_JWT_LOGIN_URL)
	fmt.Printf("    CLI X.509 Certificate Login JWT Role: %s\n", signer.DEFAULT_SIGNER_VAULT_JWT_ROLE)
	fmt.Printf("    CLI X.509 Certificate PKI Name: %s\n", signer.DEFAULT_SIGNER_VAULT_PKI_NAME)
	fmt.Printf("    CLI X.509 Certificate PKI Role: %s\n", signer.DEFAULT_SIGNER_VAULT_PKI_ROLE)
	fmt.Printf("    CLI X.509 Certificate Signer URL: %s\n", signer.DEFAULT_SIGNER_VAULT_SIGN_URL)
	fmt.Printf("    CLI X.509 Certificate CA URL: %s\n", signer.DEFAULT_SIGNER_VAULT_CA_URL)
	fmt.Printf("    CLI X.509 Certificate Issuer Reference: %s\n", signer.DEFAULT_SIGNER_VAULT_ISSUER_REF)
	fmt.Printf("    CLI X.509 Certificate TTL: %s\n", signer.DEFAULT_SIGNER_VAULT_TTL)
	fmt.Printf("    CLI X.509 Certificate Request Timeout: %s seconds\n", signer.DEFAULT_SIGNER_VAULT_TIMEOUT)
}
