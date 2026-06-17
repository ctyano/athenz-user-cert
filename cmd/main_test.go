package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctyano/athenz-user-cert/pkg/certificate"
	appconfig "github.com/ctyano/athenz-user-cert/pkg/config"
	"github.com/ctyano/athenz-user-cert/pkg/oidc"
	"github.com/ctyano/athenz-user-cert/pkg/signer"
)

func TestDefaultString(t *testing.T) {
	if got := defaultString("configured", "fallback"); got != "configured" {
		t.Fatalf("expected configured value, got %q", got)
	}
	if got := defaultString("   ", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback value, got %q", got)
	}
}

func TestBuildAthenzExternalCommonName(t *testing.T) {
	userCN, err := buildAthenzUserCommonName("user", "alice")
	if err != nil {
		t.Fatalf("buildAthenzUserCommonName returned error: %v", err)
	}
	if userCN != "user.alice" {
		t.Fatalf("expected user common name, got %q", userCN)
	}
	if _, err := buildAthenzUserCommonName("", "alice"); err == nil {
		t.Fatal("expected missing user domain to return an error")
	}

	got, err := buildAthenzExternalCommonName("corp.domain", "alice")
	if err != nil {
		t.Fatalf("buildAthenzExternalCommonName returned error: %v", err)
	}
	if got != "corp.domain:ext.alice" {
		t.Fatalf("expected common name, got %q", got)
	}

	if _, err := buildAthenzExternalCommonName("", "alice"); err == nil {
		t.Fatal("expected missing domain to return an error")
	}
	if _, err := buildAthenzExternalCommonName("corp.domain", " "); err == nil {
		t.Fatal("expected empty claim value to return an error")
	}
}

func TestAthenzCNFlagsUseConfigDefaults(t *testing.T) {
	flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := addCommandFlags(flagSet, &appconfig.Settings{
		CNMode:           "external",
		UserClaim:        "name",
		UserDomain:       "config.user.domain",
		ExternalIDDomain: "config.domain",
		ExternalIDClaim:  "email",
	})
	if err := flagSet.Parse(nil); err != nil {
		t.Fatalf("flag parse returned error: %v", err)
	}
	if *flags.signer.cnMode != "external" {
		t.Fatalf("expected CN mode from config, got %q", *flags.signer.cnMode)
	}
	if *flags.signer.identityClaim != "" {
		t.Fatalf("expected empty claim flag default, got %q", *flags.signer.identityClaim)
	}
	if flags.signer.userClaimDefault != "name" {
		t.Fatalf("expected user claim default from config, got %q", flags.signer.userClaimDefault)
	}
	if *flags.signer.userDomain != "config.user.domain" {
		t.Fatalf("expected Athenz user domain from config, got %q", *flags.signer.userDomain)
	}
	if *flags.signer.externalIDDomain != "config.domain" {
		t.Fatalf("expected Athenz external ID domain from config, got %q", *flags.signer.externalIDDomain)
	}
	if flags.signer.externalIDClaimDefault != "email" {
		t.Fatalf("expected external ID claim default from config, got %q", flags.signer.externalIDClaimDefault)
	}
}

func TestAthenzCNFlagsUseCommandLineOverrides(t *testing.T) {
	flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := addCommandFlags(flagSet, &appconfig.Settings{})
	if err := flagSet.Parse([]string{
		"-athenz-cn-mode", "external",
		"-athenz-user-domain", "flag.user.domain",
		"-athenz-external-id-domain", "flag.domain",
		"-claim", "sub",
	}); err != nil {
		t.Fatalf("flag parse returned error: %v", err)
	}
	if *flags.signer.cnMode != "external" {
		t.Fatalf("expected CN mode from flag, got %q", *flags.signer.cnMode)
	}
	if *flags.signer.userDomain != "flag.user.domain" {
		t.Fatalf("expected Athenz user domain from flag, got %q", *flags.signer.userDomain)
	}
	if *flags.signer.externalIDDomain != "flag.domain" {
		t.Fatalf("expected Athenz external ID domain from flag, got %q", *flags.signer.externalIDDomain)
	}
	if *flags.signer.identityClaim != "sub" {
		t.Fatalf("expected identity claim from flag, got %q", *flags.signer.identityClaim)
	}
}

func TestResolveSignerEndpoints(t *testing.T) {
	tests := []struct {
		name         string
		signer       string
		wantEndpoint string
		wantCA       string
	}{
		{name: "crypki", signer: "crypki", wantEndpoint: "http://localhost:10000/v3/sig/x509-cert/keys/x509-key", wantCA: "http://localhost:10000/v3/sig/x509-cert/keys/x509-key"},
		{name: "cfssl", signer: "cfssl", wantEndpoint: "http://localhost:10000/api/v1/cfssl/sign", wantCA: "http://localhost:10000/api/v1/cfssl/info"},
		{name: "zts", signer: "zts", wantEndpoint: "https://127.0.0.1:4443/zts/v1/usercert", wantCA: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signerName := tt.signer
			endpoint := ""
			caEndpoint := ""
			resolveSignerEndpoints(&signerName, &endpoint, &caEndpoint)
			if endpoint != tt.wantEndpoint {
				t.Fatalf("expected endpoint %q, got %q", tt.wantEndpoint, endpoint)
			}
			if caEndpoint != tt.wantCA {
				t.Fatalf("expected CA endpoint %q, got %q", tt.wantCA, caEndpoint)
			}
		})
	}
}

func TestSignerTLSCAFlagUsesBuildDefault(t *testing.T) {
	restore := saveCmdGlobals()
	defer restore()

	home := t.TempDir()
	t.Setenv("HOME", home)
	signer.DEFAULT_SIGNER_TLS_CA_PATH = ".athenz/ca.cert.pem"
	flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := addCommandFlags(flagSet, &appconfig.Settings{})
	if err := flagSet.Parse(nil); err != nil {
		t.Fatalf("flag parse returned error: %v", err)
	}
	if want := filepath.Join(home, ".athenz/ca.cert.pem"); *flags.signer.signerTLSCAPath != want {
		t.Fatalf("expected signer TLS CA default, got %q", *flags.signer.signerTLSCAPath)
	}
}

func TestOIDCIssuerFlag(t *testing.T) {
	t.Run("uses config value as default", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()

		flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
		flags := addCommandFlags(flagSet, &appconfig.Settings{OIDCIssuer: "https://issuer.config.example"})
		if err := flagSet.Parse(nil); err != nil {
			t.Fatalf("flag parse returned error: %v", err)
		}
		if *flags.oidcIssuer != "https://issuer.config.example" {
			t.Fatalf("expected issuer from config, got %q", *flags.oidcIssuer)
		}
	})

	t.Run("overrides package default", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()

		oidc.DEFAULT_OIDC_ISSUER = "https://issuer.default.example"
		flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
		flags := addCommandFlags(flagSet, &appconfig.Settings{})
		if err := flagSet.Parse([]string{"-oidc-issuer", "https://issuer.flag.example"}); err != nil {
			t.Fatalf("flag parse returned error: %v", err)
		}

		applyOIDCFlagOverrides(flags)

		if oidc.DEFAULT_OIDC_ISSUER != "https://issuer.flag.example" {
			t.Fatalf("expected issuer from flag, got %q", oidc.DEFAULT_OIDC_ISSUER)
		}
	})

	t.Run("execute applies override before authentication", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()
		installDefaultCommandStubs(t)

		getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
			if oidc.DEFAULT_OIDC_ISSUER != "https://issuer.flag.example" {
				t.Fatalf("expected issuer override before auth, got %q", oidc.DEFAULT_OIDC_ISSUER)
			}
			return "", io.EOF
		}

		var output bytes.Buffer
		err := execute([]string{"-oidc-issuer", "https://issuer.flag.example"}, &output, &appconfig.Settings{})
		if err == nil {
			t.Fatal("expected execute to fail after auth stub")
		}
	})
}

func TestExecuteVersionCommand(t *testing.T) {
	output := captureStdout(t, func() {
		ExecuteVersionCommand(nil, flag.NewFlagSet("version", flag.ContinueOnError))
	})

	if !strings.Contains(output, "CLI version: "+VERSION) {
		t.Fatalf("expected version output, got %q", output)
	}
	if !strings.Contains(output, "CLI Open ID Connect Issuer:") {
		t.Fatalf("expected OIDC output, got %q", output)
	}
	if !strings.Contains(output, "CLI X.509 configuration for ZTS:") {
		t.Fatalf("expected signer output, got %q", output)
	}
}

func TestExecutePasswordGrant(t *testing.T) {
	t.Run("crypki issues certificate with stdin password", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()
		installDefaultCommandStubs(t)
		installSuccessfulGenerateCSR(t)

		passwordInputReader = strings.NewReader("secret\n")
		getPasswordGrantAccessToken = func(username, password string, debug *bool) (string, error) {
			if username != "dex-user" || password != "secret" {
				t.Fatalf("unexpected password grant credentials %q/%q", username, password)
			}
			return "jwt-token", nil
		}
		getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
			t.Fatal("did not expect auth code flow when username is set")
			return "", nil
		}
		sendCrypkiCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
			if got := (*headers)["Authorization"][0]; got != "Bearer jwt-token" {
				t.Fatalf("expected crypki authorization header, got %q", got)
			}
			if !strings.Contains(csr, "Y3NyLXBheWxvYWQ=") {
				t.Fatalf("expected PEM encoded csr, got %q", csr)
			}
			return nil, "cert"
		}
		getCrypkiRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
			if test {
				t.Fatal("expected non-test CA retrieval after certificate issuance")
			}
			if got := (*headers)["Authorization"][0]; got != "Bearer jwt-token" {
				t.Fatalf("expected crypki authorization header, got %q", got)
			}
			return nil, "ca"
		}

		var output bytes.Buffer
		err := execute([]string{"-signer", "crypki", "-oidc-user", "dex-user", "-oidc-password-stdin", "-debug"}, &output, &appconfig.Settings{})
		if err != nil {
			t.Fatalf("execute returned error: %v", err)
		}
		if !strings.Contains(output.String(), "Access Token retrieved Successfully") {
			t.Fatalf("expected access token debug output, got %q", output.String())
		}
		if !strings.Contains(output.String(), "Signed Athenz User certificate is successfully stored at:") {
			t.Fatalf("expected saved certificate output, got %q", output.String())
		}
	})

	t.Run("zts issues certificate with stdin password", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()
		installDefaultCommandStubs(t)
		installSuccessfulGenerateCSR(t)

		passwordInputReader = strings.NewReader("secret\n")
		getPasswordGrantAccessToken = func(username, password string, debug *bool) (string, error) {
			if username != "dex-user" || password != "secret" {
				t.Fatalf("unexpected password grant credentials %q/%q", username, password)
			}
			return "jwt-token", nil
		}
		getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
			t.Fatal("did not expect auth code flow when username is set")
			return "", nil
		}
		sendZTSCSR = func(name, endpoint, csr, attestationData, signerTLSCAPath string, headers *map[string][]string) (error, string) {
			if name != "user.alice" {
				t.Fatalf("expected derived common name, got %q", name)
			}
			if attestationData != "jwt-token" {
				t.Fatalf("expected token attestation data, got %q", attestationData)
			}
			if !strings.Contains(csr, "Y3NyLXBheWxvYWQ=") {
				t.Fatalf("expected PEM encoded csr, got %q", csr)
			}
			return nil, "cert"
		}
		getZTSRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
			if test {
				t.Fatal("expected non-test CA retrieval after certificate issuance")
			}
			return nil, "ca"
		}

		var output bytes.Buffer
		err := execute([]string{"-signer", "zts", "-oidc-user", "dex-user", "-oidc-password-stdin"}, &output, &appconfig.Settings{})
		if err != nil {
			t.Fatalf("execute returned error: %v", err)
		}
		if !strings.Contains(output.String(), "Signed Athenz User certificate is successfully stored at:") {
			t.Fatalf("expected saved certificate output, got %q", output.String())
		}
	})
}

func TestRunMain(t *testing.T) {
	t.Run("load config failure", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()

		loadConfig = func() (*appconfig.Settings, error) {
			return nil, io.EOF
		}

		var output bytes.Buffer
		if got := runMain(nil, &output); got != 1 {
			t.Fatalf("expected exit code 1, got %d", got)
		}
		if !strings.Contains(output.String(), "Failed to load configuration") {
			t.Fatalf("expected load error output, got %q", output.String())
		}
	})

	t.Run("execute failure", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()
		installDefaultCommandStubs(t)

		loadConfig = func() (*appconfig.Settings, error) {
			return &appconfig.Settings{}, nil
		}
		getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
			return "", io.EOF
		}

		var output bytes.Buffer
		if got := runMain([]string{"-signer", "cfssl"}, &output); got != 1 {
			t.Fatalf("expected exit code 1, got %d", got)
		}
		if !strings.Contains(output.String(), "Failed to get access token") {
			t.Fatalf("expected execute error output, got %q", output.String())
		}
	})

	t.Run("success", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()
		installDefaultCommandStubs(t)

		loadConfig = func() (*appconfig.Settings, error) {
			return &appconfig.Settings{}, nil
		}
		getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
			return "cached-token", nil
		}
		sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
			return nil, "cfssl-cert"
		}
		getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
			return nil, ""
		}
		generateCSR = func(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *crypto.PrivateKey, *pem.Block) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate test private key: %v", err)
			}
			var key crypto.PrivateKey = privateKey
			return nil, &key, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("csr-payload")}
		}

		var output bytes.Buffer
		if got := runMain([]string{"-signer", "cfssl"}, &output); got != 0 {
			t.Fatalf("expected exit code 0, got %d", got)
		}
		if !strings.Contains(output.String(), "Signed Athenz User certificate is successfully stored at:") {
			t.Fatalf("expected success output, got %q", output.String())
		}
	})
}

func TestMainUsesExitFunc(t *testing.T) {
	restore := saveCmdGlobals()
	defer restore()
	installDefaultCommandStubs(t)

	originalArgs := os.Args
	os.Args = []string{"athenzusercert", "-signer", "cfssl"}
	t.Cleanup(func() {
		os.Args = originalArgs
	})

	loadConfig = func() (*appconfig.Settings, error) {
		return &appconfig.Settings{}, nil
	}
	getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
		return "cached-token", nil
	}
	sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
		return nil, "cfssl-cert"
	}
	getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
		return nil, ""
	}
	generateCSR = func(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *crypto.PrivateKey, *pem.Block) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate test private key: %v", err)
		}
		var key crypto.PrivateKey = privateKey
		return nil, &key, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("csr-payload")}
	}

	exitCode := -1
	exitFunc = func(code int) {
		exitCode = code
	}

	output := captureStdout(t, func() {
		main()
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "Signed Athenz User certificate is successfully stored at:") {
		t.Fatalf("expected success output, got %q", output)
	}
}

func TestExecuteHelp(t *testing.T) {
	var output bytes.Buffer

	if err := execute([]string{"help"}, &output, &appconfig.Settings{}); err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if !strings.Contains(output.String(), "Usage of "+DEFAULT_APP_NAME) {
		t.Fatalf("expected help output, got %q", output.String())
	}
	if !strings.Contains(output.String(), "-signer") {
		t.Fatalf("expected help flags in output, got %q", output.String())
	}
}

func TestExecuteSignerFlows(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantCommonName  string
		wantCert        string
		wantCACert      string
		wantAccessToken string
		wantCAUpdated   bool
		setup           func(*testing.T)
	}{
		{
			name:            "crypki",
			args:            []string{"-signer", "crypki", "-debug"},
			wantCommonName:  "user.alice",
			wantCert:        "crypki-cert",
			wantCACert:      "crypki-ca",
			wantAccessToken: "cached-token",
			wantCAUpdated:   true,
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCrypkiCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "crypki-cert"
				}
				getCrypkiRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, "crypki-ca"
				}
			},
		},
		{
			name:            "cfssl",
			args:            []string{"-signer", "cfssl"},
			wantCommonName:  "user.alice",
			wantCert:        "cfssl-cert",
			wantCACert:      "cfssl-ca",
			wantAccessToken: "cached-token",
			wantCAUpdated:   true,
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-ca"
				}
			},
		},
		{
			name:            "cfssl with external CN mode",
			args:            []string{"-signer", "cfssl", "-athenz-cn-mode", "external", "-athenz-external-id-domain", "external.id.domain"},
			wantCommonName:  "external.id.domain:ext.alice",
			wantCert:        "cfssl-cert",
			wantCACert:      "cfssl-ca",
			wantAccessToken: "cached-token",
			wantCAUpdated:   true,
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-ca"
				}
			},
		},
		{
			name:            "zts with derived common name",
			args:            []string{"-signer", "zts", "-debug"},
			wantCommonName:  "user.alice",
			wantCert:        "zts-cert",
			wantCACert:      "",
			wantAccessToken: "cached-token",
			wantCAUpdated:   false,
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendZTSCSR = func(name, endpoint, csr, attestationData, signerTLSCAPath string, headers *map[string][]string) (error, string) {
					if attestationData != "cached-token" {
						t.Fatalf("expected access token attestation data, got %q", attestationData)
					}
					return nil, "zts-cert"
				}
				getZTSRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, ""
				}
			},
		},
		{
			name:            "zts with explicit common name",
			args:            []string{"-signer", "zts", "-cn", "custom.name"},
			wantCommonName:  "custom.name",
			wantCert:        "zts-cert",
			wantCACert:      "zts-ca",
			wantAccessToken: "cached-token",
			wantCAUpdated:   true,
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				getExternalIDFromAccessToken = func(rawJWT, externalIDClaim string) (string, error) {
					t.Fatal("did not expect external ID extraction when common name is provided")
					return "", nil
				}
				getUserNameFromAccessToken = func(rawJWT, userNameClaim string) (string, error) {
					t.Fatal("did not expect user name extraction when common name is provided")
					return "", nil
				}
				sendZTSCSR = func(name, endpoint, csr, attestationData, signerTLSCAPath string, headers *map[string][]string) (error, string) {
					if attestationData != "cached-token" {
						t.Fatalf("expected access token attestation data, got %q", attestationData)
					}
					return nil, "zts-cert"
				}
				getZTSRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, "zts-ca"
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := saveCmdGlobals()
			defer restore()
			installDefaultCommandStubs(t)
			tt.setup(t)

			var writtenFiles = map[string]string{}
			writeOutputFile = func(path string, data []byte, perm os.FileMode) error {
				writtenFiles[path] = string(data)
				return nil
			}

			var sentCommonName string
			generateCSR = func(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *crypto.PrivateKey, *pem.Block) {
				sentCommonName = *cn
				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("failed to generate test private key: %v", err)
				}
				var key crypto.PrivateKey = privateKey
				return nil, &key, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("csr-payload")}
			}

			var output bytes.Buffer
			err := execute(tt.args, &output, &appconfig.Settings{})
			if err != nil {
				t.Fatalf("execute returned error: %v", err)
			}

			if sentCommonName != tt.wantCommonName {
				t.Fatalf("expected common name %q, got %q", tt.wantCommonName, sentCommonName)
			}
			if got := writtenFiles[userCertPath()]; got != tt.wantCert {
				t.Fatalf("expected written certificate %q, got %q", tt.wantCert, got)
			}
			if tt.wantCAUpdated {
				if got := writtenFiles[caCertPath()]; got != tt.wantCACert {
					t.Fatalf("expected written CA certificate %q, got %q", tt.wantCACert, got)
				}
			} else if _, ok := writtenFiles[caCertPath()]; ok {
				t.Fatalf("did not expect CA certificate to be written")
			}
			if !strings.Contains(output.String(), "Signed Athenz User certificate is successfully stored at:") {
				t.Fatalf("expected success output, got %q", output.String())
			}
		})
	}
}

func TestExecuteReturnsError(t *testing.T) {
	restore := saveCmdGlobals()
	defer restore()
	installDefaultCommandStubs(t)

	getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
		return "cached-token", nil
	}
	sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
		return io.EOF, ""
	}

	var output bytes.Buffer
	err := execute([]string{"-signer", "cfssl"}, &output, &appconfig.Settings{})
	if err == nil {
		t.Fatal("expected execute to return an error")
	}
	if !strings.Contains(err.Error(), "Failed to get signed certificate") {
		t.Fatalf("expected signer error, got %v", err)
	}
}

func TestExecuteSubcommands(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		var output bytes.Buffer
		if err := execute([]string{"version"}, &output, &appconfig.Settings{}); err != nil {
			t.Fatalf("execute returned error: %v", err)
		}
	})
}

func TestExecuteAdditionalErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
		setup   func(*testing.T)
	}{
		{
			name:    "flag parse error",
			args:    []string{"-unknown-flag"},
			wantErr: "flag provided but not defined",
			setup:   func(*testing.T) {},
		},
		{
			name:    "zts access token missing",
			args:    []string{"-signer", "zts"},
			wantErr: "Failed to get access token",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "", nil
				}
			},
		},
		{
			name:    "zts explicit common name access token missing",
			args:    []string{"-signer", "zts", "-cn", "custom.name"},
			wantErr: "Failed to get access token",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "", nil
				}
			},
		},
		{
			name:    "user name extraction error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to extract Athenz user name",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				getUserNameFromAccessToken = func(rawJWT, userNameClaim string) (string, error) {
					return "", io.EOF
				}
			},
		},
		{
			name:    "external ID extraction error",
			args:    []string{"-signer", "cfssl", "-athenz-cn-mode", "external"},
			wantErr: "Failed to extract Athenz external ID",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				getExternalIDFromAccessToken = func(rawJWT, externalIDClaim string) (string, error) {
					return "", io.EOF
				}
			},
		},
		{
			name:    "missing Athenz external ID domain",
			args:    []string{"-signer", "cfssl", "-athenz-cn-mode", "external"},
			wantErr: "Athenz external ID domain is required",
			setup: func(t *testing.T) {
				certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN = ""
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
			},
		},
		{
			name:    "unsupported CN mode",
			args:    []string{"-signer", "cfssl", "-athenz-cn-mode", "invalid"},
			wantErr: "unsupported Athenz CN mode",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
			},
		},
		{
			name:    "generate csr error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to generate csr",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				generateCSR = func(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *crypto.PrivateKey, *pem.Block) {
					return io.EOF, nil, nil
				}
			},
		},
		{
			name:    "private key pem error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to convert X.509 certificate key to PEM string",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, ""
				}
				privateKeyToPEM = func(priv crypto.PrivateKey) (*pem.Block, error) {
					return nil, io.EOF
				}
			},
		},
		{
			name:    "write key pem error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to save X.509 certificate key",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, ""
				}
				writePEMFile = func(block *pem.Block, path string) error {
					return io.EOF
				}
			},
		},
		{
			name:    "write cert error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to save X.509 certificate to",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, ""
				}
				writeOutputFile = func(path string, data []byte, perm os.FileMode) error {
					if path == userCertPath() {
						return io.EOF
					}
					return nil
				}
			},
		},
		{
			name:    "write ca cert error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to save X.509 CA certificate to",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-ca"
				}
				writeOutputFile = func(path string, data []byte, perm os.FileMode) error {
					if path == caCertPath() {
						return io.EOF
					}
					return nil
				}
			},
		},
		{
			name:    "ca retrieval error",
			args:    []string{"-signer", "crypki"},
			wantErr: "Failed to get ca certificate",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCrypkiCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "crypki-cert"
				}
				getCrypkiRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return io.EOF, ""
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := saveCmdGlobals()
			defer restore()
			installDefaultCommandStubs(t)
			installSuccessfulGenerateCSR(t)
			tt.setup(t)

			var output bytes.Buffer
			err := execute(tt.args, &output, &appconfig.Settings{})
			if err == nil {
				t.Fatal("expected execute to return an error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func installSuccessfulGenerateCSR(t *testing.T) {
	t.Helper()

	generateCSR = func(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *crypto.PrivateKey, *pem.Block) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate test private key: %v", err)
		}
		var key crypto.PrivateKey = privateKey
		return nil, &key, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("csr-payload")}
	}
}

func installDefaultCommandStubs(t *testing.T) {
	t.Helper()

	getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
		return "", io.EOF
	}
	getPasswordGrantAccessToken = func(username, password string, debug *bool) (string, error) {
		return "", io.EOF
	}
	getExternalIDFromAccessToken = func(rawJWT, externalIDClaim string) (string, error) {
		if rawJWT == "" {
			t.Fatal("expected access token for external ID extraction")
		}
		return "alice", nil
	}
	getUserNameFromAccessToken = func(rawJWT, userNameClaim string) (string, error) {
		if rawJWT == "" {
			t.Fatal("expected access token for user name extraction")
		}
		return "alice", nil
	}
	certificate.DEFAULT_ATHENZ_CN_MODE = "user"
	certificate.DEFAULT_ATHENZ_USER_DOMAIN = "user"
	certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN = "external.id.domain"
	privateKeyToPEM = func(priv crypto.PrivateKey) (*pem.Block, error) {
		return &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("key")}, nil
	}
	writePEMFile = func(block *pem.Block, path string) error { return nil }
	userKeyPath = func() string { return "/tmp/user.key.pem" }
	userCertPath = func() string { return "/tmp/user.cert.pem" }
	caCertPath = func() string { return "/tmp/ca.cert.pem" }
	writeOutputFile = func(path string, data []byte, perm os.FileMode) error { return nil }
	sendCrypkiCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) { return io.EOF, "" }
	getCrypkiRootCA = func(test bool, source string, headers *map[string][]string) (error, string) { return io.EOF, "" }
	sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) { return io.EOF, "" }
	getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) { return io.EOF, "" }
	sendZTSCSR = func(name, endpoint, csr, attestationData, signerTLSCAPath string, headers *map[string][]string) (error, string) {
		return io.EOF, ""
	}
	getZTSRootCA = func(test bool, source string, headers *map[string][]string) (error, string) { return io.EOF, "" }
}

func saveCmdGlobals() func() {
	savedLoadConfig := loadConfig
	savedGetAuthAccessToken := getAuthAccessToken
	savedGetPasswordGrantAccessToken := getPasswordGrantAccessToken
	savedGetExternalIDFromAccessToken := getExternalIDFromAccessToken
	savedGetUserNameFromAccessToken := getUserNameFromAccessToken
	savedGenerateCSR := generateCSR
	savedPrivateKeyToPEM := privateKeyToPEM
	savedWritePEMFile := writePEMFile
	savedUserKeyPath := userKeyPath
	savedUserCertPath := userCertPath
	savedCACertPath := caCertPath
	savedWriteOutputFile := writeOutputFile
	savedSendCrypkiCSR := sendCrypkiCSR
	savedGetCrypkiRootCA := getCrypkiRootCA
	savedSendCFSSLCSR := sendCFSSLCSR
	savedGetCFSSLRootCA := getCFSSLRootCA
	savedSendZTSCSR := sendZTSCSR
	savedGetZTSRootCA := getZTSRootCA
	savedSignerTLSCAPath := signer.DEFAULT_SIGNER_TLS_CA_PATH
	savedOIDCIssuer := oidc.DEFAULT_OIDC_ISSUER
	savedAthenzCNMode := certificate.DEFAULT_ATHENZ_CN_MODE
	savedAthenzUserDomain := certificate.DEFAULT_ATHENZ_USER_DOMAIN
	savedExternalIDDomain := certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN
	savedExitFunc := exitFunc
	savedPasswordInputReader := passwordInputReader

	return func() {
		loadConfig = savedLoadConfig
		getAuthAccessToken = savedGetAuthAccessToken
		getPasswordGrantAccessToken = savedGetPasswordGrantAccessToken
		getExternalIDFromAccessToken = savedGetExternalIDFromAccessToken
		getUserNameFromAccessToken = savedGetUserNameFromAccessToken
		generateCSR = savedGenerateCSR
		privateKeyToPEM = savedPrivateKeyToPEM
		writePEMFile = savedWritePEMFile
		userKeyPath = savedUserKeyPath
		userCertPath = savedUserCertPath
		caCertPath = savedCACertPath
		writeOutputFile = savedWriteOutputFile
		sendCrypkiCSR = savedSendCrypkiCSR
		getCrypkiRootCA = savedGetCrypkiRootCA
		sendCFSSLCSR = savedSendCFSSLCSR
		getCFSSLRootCA = savedGetCFSSLRootCA
		sendZTSCSR = savedSendZTSCSR
		getZTSRootCA = savedGetZTSRootCA
		signer.DEFAULT_SIGNER_TLS_CA_PATH = savedSignerTLSCAPath
		oidc.DEFAULT_OIDC_ISSUER = savedOIDCIssuer
		certificate.DEFAULT_ATHENZ_CN_MODE = savedAthenzCNMode
		certificate.DEFAULT_ATHENZ_USER_DOMAIN = savedAthenzUserDomain
		certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN = savedExternalIDDomain
		exitFunc = savedExitFunc
		passwordInputReader = savedPasswordInputReader
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	os.Stdout = writer
	defer func() {
		os.Stdout = originalStdout
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close stdout writer: %v", err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read stdout: %v", err)
	}

	return string(data)
}
