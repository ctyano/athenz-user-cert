package main

import (
	"bufio"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ctyano/athenz-user-cert/pkg/certificate"
	appconfig "github.com/ctyano/athenz-user-cert/pkg/config"
	"github.com/ctyano/athenz-user-cert/pkg/oidc"
	"github.com/ctyano/athenz-user-cert/pkg/signer"
)

var (
	DEFAULT_APP_NAME    = "athenzusercert"
	DEFAULT_SIGNER_NAME = "zts"

	loadConfig                   = appconfig.Load
	getAuthAccessToken           = oidc.GetAuthAccessToken
	getPasswordGrantAccessToken  = oidc.GetPasswordGrantAccessToken
	getExternalIDFromAccessToken = oidc.GetExternalIDFromAccessToken
	getUserNameFromAccessToken   = oidc.GetUserNameFromAccessToken
	generateCSR                  = certificate.GenerateCSR
	privateKeyToPEM              = certificate.PrivateKeyToPEM
	writePEMFile                 = certificate.WritePEM
	userKeyPath                  = certificate.UserKeyPath
	userCertPath                 = certificate.UserCertPath
	caCertPath                   = certificate.CACertPath
	writeOutputFile              = os.WriteFile
	sendCrypkiCSR                = signer.SendCrypkiCSR
	getCrypkiRootCA              = signer.GetCrypkiRootCA
	sendCFSSLCSR                 = signer.SendCFSSLCSR
	getCFSSLRootCA               = signer.GetCFSSLRootCA
	sendZTSCSR                   = signer.SendZTSCSR
	getZTSRootCA                 = signer.GetZTSRootCA
	exitFunc                     = os.Exit
	passwordInputReader          = io.Reader(os.Stdin)
)

func main() {
	exitFunc(runMain(os.Args[1:], os.Stdout))
}

func runMain(args []string, stdout io.Writer) int {
	cfg, loadErr := loadConfig()
	if loadErr != nil {
		fmt.Fprintf(stdout, "Failed to load configuration: %s\n", loadErr)
		return 1
	}

	if err := execute(args, stdout, cfg); err != nil {
		fmt.Fprintln(stdout, err)
		return 1
	}
	return 0
}

func execute(args []string, stdout io.Writer, cfg *appconfig.Settings) error {
	appname := DEFAULT_APP_NAME
	usage := fmt.Sprintf(`Usage of %s:
  Generate certificate signing request and send the csr to the server.
  Authenticate user with Open ID Connect protocol and retrieve OAuth Access Token.

Subcommands:
  version:
  	Print the version and the pre desined parameters of this CLI.
  help:
  	Print this help message.

Options:
`, appname)

	if len(args) > 0 {
		switch {
		case strings.HasSuffix(args[0], "version"):
			versionFlagSet := flag.NewFlagSet("version", flag.ExitOnError)
			ExecuteVersionCommand(args[1:], versionFlagSet)
			return nil
		case strings.HasSuffix(args[0], "help"):
			fmt.Fprintln(stdout, usage)
			flagSet := flag.NewFlagSet(appname, flag.ContinueOnError)
			flagSet.SetOutput(stdout)
			addCommandFlags(flagSet, cfg)
			flagSet.PrintDefaults()
			return nil
		}
	}

	// Parse argument flags
	flagSet := flag.NewFlagSet(appname, flag.ContinueOnError)
	flagSet.SetOutput(stdout)
	flags := addCommandFlags(flagSet, cfg)
	if err := flagSet.Parse(args); err != nil {
		return err
	}
	applyOIDCFlagOverrides(flags)

	var accesstoken string
	var err error
	accesstoken, err = getCommandAccessToken(flags)
	if err != nil || accesstoken == "" {
		return fmt.Errorf("Failed to get access token: %v", err)
	}
	if *flags.signer.debug {
		fmt.Fprintf(stdout, "Access Token retrieved Successfully:\n%s\n", accesstoken)
	}

	if err := setCommonNameFromAccessToken(accesstoken, flags.signer, stdout); err != nil {
		return err
	}

	err, key, csrPEM := generateCSR("", flags.signer.commonName, flags.dnsarg, flags.emailarg, flags.iparg, flags.uriarg)
	if err != nil {
		return fmt.Errorf("Failed to generate csr: %v", err)
	}
	csr := strings.TrimSuffix(string(pem.EncodeToMemory(csrPEM)), "\n")
	if *flags.signer.debug {
		fmt.Fprintf(stdout, "Generated csr:\n%s\n", csr)
	}

	prepareSignerConfig(flags.signer, stdout)

	var cert, cacert string
	switch *flags.signer.signerName {
	case "crypki":
		err, cert = sendCrypkiCSR(*flags.signer.endpoint, csr, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get signed certificate: %v", err)
		}
		if *flags.signer.debug {
			fmt.Fprintf(stdout, "Signed certificate:\n%s\n", cert)
		}
		err, cacert = getCrypkiRootCA(false, *flags.signer.caEndpoint, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
		if *flags.signer.debug {
			fmt.Fprintf(stdout, "CA certificate:\n%s\n", cacert)
		}
	case "cfssl":
		err, cert = sendCFSSLCSR(*flags.signer.endpoint, csr, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get signed certificate: %v", err)
		}
		if *flags.signer.debug {
			fmt.Fprintf(stdout, "Signed certificate:\n%s\n", cert)
		}
		err, cacert = getCFSSLRootCA(false, *flags.signer.caEndpoint, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
		if *flags.signer.debug {
			fmt.Fprintf(stdout, "CA certificate:\n%s\n", cacert)
		}
	case "zts":
		err, cert = sendZTSCSR(*flags.signer.commonName, *flags.signer.endpoint, csr, accesstoken, *flags.signer.signerTLSCAPath, nil)
		if err != nil {
			return fmt.Errorf("Failed to get signed certificate: %v", err)
		}
		if *flags.signer.debug {
			fmt.Fprintf(stdout, "Signed certificate:\n%s\n", cert)
		}
		err, cacert = getZTSRootCA(false, *flags.signer.caEndpoint, nil)
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
		if *flags.signer.debug {
			fmt.Fprintf(stdout, "CA certificate:\n%s\n", cacert)
		}
	case "vault":
		err, cert = signer.SendVaultCSR(*commonName, *signerURL, csr, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			fmt.Printf("Failed to get signed certificate: %s\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("Signed certificate:\n%s\n", cert)
		}
		err, cacert = signer.GetVaultRootCA(false, *caURL, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			fmt.Printf("Failed to get ca certificate: %s\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("CA certificate:\n%s\n", cacert)
		}
	}

	keyPEM, err := privateKeyToPEM(*key)
	if err != nil {
		return fmt.Errorf("Failed to convert X.509 certificate key to PEM string: %v", err)
	}
	keyDestination := userKeyPath()
	err = writePEMFile(keyPEM, keyDestination)
	if err != nil {
		return fmt.Errorf("Failed to save X.509 certificate key to %s: %v", keyDestination, err)
	}

	certDestination := userCertPath()
	err = writeOutputFile(certDestination, []byte(cert), 0600)
	if err != nil {
		return fmt.Errorf("Failed to save X.509 certificate to %s: %v", certDestination, err)
	}
	caCertDestination := caCertPath()

	if cacert != "" {
		err = writeOutputFile(caCertDestination, []byte(cacert), 0600)
		if err != nil {
			return fmt.Errorf("Failed to save X.509 CA certificate to %s: %v", caCertDestination, err)
		}
	}

	fmt.Fprintf(stdout, "Signed Athenz User certificate key is successfully stored at: \t%s\n", keyDestination)
	fmt.Fprintf(stdout, "Signed Athenz User certificate is successfully stored at: \t%s\n", certDestination)
	if cacert != "" {
		fmt.Fprintf(stdout, "Signed Athenz CA certificate is successfully stored at: \t%s\n", caCertDestination)
	} else {
		fmt.Fprintf(stdout, "Signed Athenz CA certificate was not updated. Use -ca-endpoint if you need to refresh %s\n", caCertDestination)
	}

	return nil
}

type signerCommandFlags struct {
	signerName             *string
	endpoint               *string
	caEndpoint             *string
	signerTLSCAPath        *string
	commonName             *string
	cnMode                 *string
	identityClaim          *string
	userDomain             *string
	externalIDDomain       *string
	userClaimDefault       string
	externalIDClaimDefault string
	debug                  *bool
}

type mainCommandFlags struct {
	signer        signerCommandFlags
	dnsarg        *string
	emailarg      *string
	iparg         *string
	uriarg        *string
	responseMode  *string
	oidcIssuer    *string
	oidcUser      *string
	oidcPassStdin *bool
}

func addCommandFlags(flagSet *flag.FlagSet, cfg *appconfig.Settings) mainCommandFlags {
	flags := mainCommandFlags{
		signer: addSignerCommandFlags(flagSet, cfg, "user"),
	}
	flags.dnsarg = flagSet.String("dns", "", "Comma-separated SANs(Subject Alternative Names) as hostnames for the certificate")
	flags.emailarg = flagSet.String("email", "", "Comma-separated SANs(Subject Alternative Names) as Emails for the certificate")
	flags.iparg = flagSet.String("ip", "", "Comma-separated SANs(Subject Alternative Names) as IPs for the certificate")
	flags.uriarg = flagSet.String("uri", "", "Comma-separated SANs(Subject Alternative Names) as URIs for the certificate")
	flags.responseMode = flagSet.String("response-mode", defaultString(cfg.ResponseMode, "form_post"), "OAuth2 response_mode (\"query\" or \"form_post\")")
	flags.oidcIssuer = flagSet.String("oidc-issuer", defaultString(cfg.OIDCIssuer, oidc.DEFAULT_OIDC_ISSUER), "OpenID Connect issuer URL")
	flags.oidcUser = flagSet.String("oidc-user", "", "OIDC user for password grant")
	flags.oidcPassStdin = flagSet.Bool("oidc-password-stdin", false, "Read the OIDC password for password grant from stdin")
	return flags
}

func addSignerCommandFlags(flagSet *flag.FlagSet, cfg *appconfig.Settings, certType string) signerCommandFlags {
	return signerCommandFlags{
		signerName:             flagSet.String("signer", defaultString(cfg.SignerName, DEFAULT_SIGNER_NAME), "Name for the certificate signer product (\"crypki\", \"cfssl\" or \"zts\")"),
		endpoint:               flagSet.String("endpoint", cfg.Endpoint, "Target destination URL to send the certificate sign request (leave it empty to use default)"),
		caEndpoint:             flagSet.String("ca-endpoint", cfg.CAEndpoint, "Target destination API endpoint to retrieve the signer-issued CA certificate (leave it empty to use default)"),
		signerTLSCAPath:        flagSet.String("signer-tls-ca", defaultString(cfg.SignerTLSCAPath, signer.DefaultSignerTLSCAPath()), "Local PEM path for the CA used to verify the signer server TLS certificate"),
		commonName:             flagSet.String("cn", "", fmt.Sprintf("Athenz User Certificate CN for the %s certificate (default depends on -athenz-cn-mode)", certType)),
		cnMode:                 flagSet.String("athenz-cn-mode", defaultString(cfg.CNMode, certificate.DEFAULT_ATHENZ_CN_MODE), "Athenz User Certificate CN derivation mode (\"user\" or \"external\")"),
		identityClaim:          flagSet.String("claim", "", "JWT Claim Name used to derive the Athenz User Certificate CN (mode-specific default if empty)"),
		userDomain:             flagSet.String("athenz-user-domain", defaultString(cfg.UserDomain, certificate.DEFAULT_ATHENZ_USER_DOMAIN), "Athenz user domain for the derived Athenz User Certificate CN"),
		externalIDDomain:       flagSet.String("athenz-external-id-domain", defaultString(cfg.ExternalIDDomain, certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN), "Athenz external ID domain for the derived Athenz User Certificate CN"),
		userClaimDefault:       defaultString(cfg.UserClaim, oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM),
		externalIDClaimDefault: defaultString(cfg.ExternalIDClaim, oidc.DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM),
		debug:                  flagSet.Bool("debug", false, "Print the access token to send the Certificate Siginig Request"),
	}
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func applyOIDCFlagOverrides(flags mainCommandFlags) {
	if flags.oidcIssuer != nil {
		oidc.DEFAULT_OIDC_ISSUER = strings.TrimSpace(*flags.oidcIssuer)
	}
}

func getCommandAccessToken(flags mainCommandFlags) (string, error) {
	if strings.TrimSpace(*flags.oidcUser) == "" && !*flags.oidcPassStdin {
		return getAuthAccessToken(flags.responseMode, flags.signer.debug)
	}
	accessToken, err := getPasswordGrantToken(*flags.oidcUser, *flags.oidcPassStdin, flags.signer.debug)
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func getPasswordGrantToken(userName string, passwordStdin bool, debug *bool) (string, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return "", fmt.Errorf("OIDC user is required for password grant (set -oidc-user)")
	}

	password, err := getPassword(passwordStdin)
	if err != nil {
		return "", err
	}
	accessToken, err := getPasswordGrantAccessToken(userName, password, debug)
	if err != nil {
		return "", err
	}
	if accessToken == "" {
		return "", fmt.Errorf("empty token")
	}
	return accessToken, nil
}

func getPassword(passwordStdin bool) (string, error) {
	if !passwordStdin {
		return "", fmt.Errorf("password is required for password grant (use -oidc-password-stdin)")
	}

	reader := bufio.NewReader(passwordInputReader)
	password, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read password from stdin: %v", err)
	}
	password = strings.TrimRight(password, "\r\n")
	if password == "" {
		return "", fmt.Errorf("password is required for password grant")
	}
	return password, nil
}

func resolveSignerEndpoints(signerName, endpoint, caEndpoint *string) {
	switch *signerName {
	case "crypki":
		if *endpoint == "" {
			*endpoint = signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL
		}
		if *caEndpoint == "" {
			*caEndpoint = signer.DEFAULT_SIGNER_CRYPKI_CA_URL
		}
	case "cfssl":
		if *endpoint == "" {
			*endpoint = signer.DEFAULT_SIGNER_CFSSL_SIGN_URL
		}
		if *caEndpoint == "" {
			*caEndpoint = signer.DEFAULT_SIGNER_CFSSL_CA_URL
		}
	case "zts":
		if *endpoint == "" {
			*endpoint = signer.DEFAULT_SIGNER_ZTS_SIGN_URL
		}
		if *caEndpoint == "" {
			*caEndpoint = signer.DEFAULT_SIGNER_ZTS_CA_URL
		}
	case "vault":
		if *signerURL == "" {
			*signerURL = signer.DEFAULT_SIGNER_VAULT_SIGN_URL
		}
		if *caURL == "" {
			*caURL = signer.DEFAULT_SIGNER_VAULT_CA_URL
		}
	}
}

func prepareSignerConfig(flags signerCommandFlags, stdout io.Writer) {
	resolveSignerEndpoints(flags.signerName, flags.endpoint, flags.caEndpoint)
	signer.DEFAULT_SIGNER_TLS_CA_PATH = strings.TrimSpace(*flags.signerTLSCAPath)
	if *flags.debug {
		fmt.Fprintf(stdout, "Signer URL is set as:%s\n", *flags.endpoint)
		fmt.Fprintf(stdout, "Signer CA endpoint is set as:%s\n", *flags.caEndpoint)
		fmt.Fprintf(stdout, "Signer TLS CA path is set as:%s\n", *flags.signerTLSCAPath)
	}
}

func setCommonNameFromAccessToken(accessToken string, flags signerCommandFlags, stdout io.Writer) error {
	if *flags.commonName != "" {
		return nil
	}
	mode, err := resolveAthenzCNMode(*flags.cnMode)
	if err != nil {
		return err
	}

	var cn string
	switch mode {
	case athenzCNModeUser:
		claim := defaultString(*flags.identityClaim, flags.userClaimDefault)
		username, err := getUserNameFromAccessToken(accessToken, claim)
		if err != nil {
			return fmt.Errorf("Failed to extract Athenz user name from Access Token: %v", err)
		}
		cn, err = buildAthenzUserCommonName(*flags.userDomain, username)
		if err != nil {
			return err
		}
	case athenzCNModeExternal:
		claim := defaultString(*flags.identityClaim, flags.externalIDClaimDefault)
		externalIDValue, err := getExternalIDFromAccessToken(accessToken, claim)
		if err != nil {
			return fmt.Errorf("Failed to extract Athenz external ID from Access Token: %v", err)
		}
		cn, err = buildAthenzExternalCommonName(*flags.externalIDDomain, externalIDValue)
		if err != nil {
			return err
		}
	}
	*flags.commonName = cn
	if *flags.debug {
		fmt.Fprintf(stdout, "Athenz User Certificate CN is: %s\n", *flags.commonName)
	}
	return nil
}

const (
	athenzCNModeUser     = "user"
	athenzCNModeExternal = "external"
)

func resolveAthenzCNMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(defaultString(mode, certificate.DEFAULT_ATHENZ_CN_MODE)))
	switch mode {
	case athenzCNModeUser, athenzCNModeExternal:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported Athenz CN mode %q (supported: %q or %q)", mode, athenzCNModeUser, athenzCNModeExternal)
	}
}

func buildAthenzUserCommonName(userDomain, username string) (string, error) {
	userDomain = strings.TrimSpace(userDomain)
	username = strings.TrimSpace(username)
	if userDomain == "" {
		return "", fmt.Errorf("Athenz user domain is required to derive Athenz User Certificate CN")
	}
	if username == "" {
		return "", fmt.Errorf("Athenz user name claim value is empty")
	}
	return userDomain + "." + username, nil
}

func buildAthenzExternalCommonName(domain, claimValue string) (string, error) {
	domain = strings.TrimSpace(domain)
	claimValue = strings.TrimSpace(claimValue)
	if domain == "" {
		return "", fmt.Errorf("Athenz external ID domain is required to derive Athenz User Certificate CN")
	}
	if claimValue == "" {
		return "", fmt.Errorf("Athenz external ID claim value is empty")
	}
	return domain + ":ext." + claimValue, nil
}
