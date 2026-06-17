# athenz-user-cert

This is an unofficial repository to provide tools, packages and instructions for [Athenz](https://www.athenz.io).

It is currently owned and maintained by [ctyano](https://github.com/ctyano).

The `athenzusercert` CLI interacts with an OAuth 2.0 Identity Provider to obtain an OAuth access token.
It then communicates with the Certificate Signer API (e.g., [certsigner-envoy](https://github.com/ctyano/certsigner-envoy)) to retrieve an X.509 certificate.
This certificate is compatible with Athenz and can be used to authenticate the user.

## How it works

[![](https://img.plantuml.biz/plantuml/svg/ZLLDRzim3BthLn3kfSNW5RtkK7JjWA5OXns6Oi3QOP1bDjQgIAu-cYP3_lj8oKxjPbyvE8hrtYFvH2fd8KeVqz88WtSHeWEl5rs4LdjKKJihHDJH85HlOuTs0zS1uKBImrdua1hq5YE6IWYfelDJcAz01aYq4FHGpAc-O0Fdtgt6tQQidm43_UBgCkyhe_VsM1ekq4T6tTh3bVFtWS5EfjX1dngZ5JFHngDT3ee91v-yj0iKGXcNMgYU2o1y2f6p-Ya0bFJjBfv78oEsG6aah-CQb5lspf9wA6Z-58Row_vUbymz75onbUyzejtX0AnhSKJMmTt5BYmB8qnG03S5ygs8yNAwEH3pxh3URM_5_Fk6QmzwOT7NlNTFwttJ-E6ytaW-SghKFw8_okAPC0gr-BJFrIrPmRuGz95-34J2phmfRkPAPJ6s-7Dk4kxPKn1rAbwckJ7SHDUNEKZIUrM_aDWiGrtgoLARkTJNZv-p3g7-9TGsMQ1jPWgjZBAPTkUxyse6e20a_hsaS6j7_1YrRIROxM-FS2ksWeV0GrtNf-F8m1keN8-sccnHp_DhVCBS_t0CnYbfEXVYS5PbAgQStMnCY3JDOvGwzIz0pv9IAGm13hiO-wCfXndwhzYTuEjJRXJ6UYntpbXWDTCRG7yKv78PHvOoJlQQsiuOM6cgEbURmosZ6JY1vZh4QIfCpztE0ln6tsb5amyyEjhg1J4U4f56WLVmOyKA8irYUvJjyOfk2XoJLCv6xmpqZcwczK0d8XC68hKLKNVTD11pzeVBTNWm7ATabqywNmZ_cIZRK_1C7MuBvkxZ-tiLJauuriYuwNHB0_wDpw0HuWnjo_yMlm00)](https://editor.plantuml.com/uml/ZLLDRzim3BthLn3kfSNW5RtkK7JjWA5OXns6Oi3QOP1bDjQgIAu-cYP3_lj8oKxjPbyvE8hrtYFvH2fd8KeVqz88WtSHeWEl5rs4LdjKKJihHDJH85HlOuTs0zS1uKBImrdua1hq5YE6IWYfelDJcAz01aYq4FHGpAc-O0Fdtgt6tQQidm43_UBgCkyhe_VsM1ekq4T6tTh3bVFtWS5EfjX1dngZ5JFHngDT3ee91v-yj0iKGXcNMgYU2o1y2f6p-Ya0bFJjBfv78oEsG6aah-CQb5lspf9wA6Z-58Row_vUbymz75onbUyzejtX0AnhSKJMmTt5BYmB8qnG03S5ygs8yNAwEH3pxh3URM_5_Fk6QmzwOT7NlNTFwttJ-E6ytaW-SghKFw8_okAPC0gr-BJFrIrPmRuGz95-34J2phmfRkPAPJ6s-7Dk4kxPKn1rAbwckJ7SHDUNEKZIUrM_aDWiGrtgoLARkTJNZv-p3g7-9TGsMQ1jPWgjZBAPTkUxyse6e20a_hsaS6j7_1YrRIROxM-FS2ksWeV0GrtNf-F8m1keN8-sccnHp_DhVCBS_t0CnYbfEXVYS5PbAgQStMnCY3JDOvGwzIz0pv9IAGm13hiO-wCfXndwhzYTuEjJRXJ6UYntpbXWDTCRG7yKv78PHvOoJlQQsiuOM6cgEbURmosZ6JY1vZh4QIfCpztE0ln6tsb5amyyEjhg1J4U4f56WLVmOyKA8irYUvJjyOfk2XoJLCv6xmpqZcwczK0d8XC68hKLKNVTD11pzeVBTNWm7ATabqywNmZ_cIZRK_1C7MuBvkxZ-tiLJauuriYuwNHB0_wDpw0HuWnjo_yMlm00)

## How to install

Install from the community Homebrew tap:

```
brew tap athenz-community/athenz-user-cert https://github.com/athenz-community/athenz-user-cert
brew install athenz-community/athenz-user-cert/athenz-user-cert
```

Or install from the personal Homebrew tap:

```
brew tap ctyano/athenz-user-cert https://github.com/ctyano/athenz-user-cert
brew install ctyano/athenz-user-cert/athenz-user-cert
```

Homebrew formulae are published by GoReleaser to this repository's `Formula` directory.
The explicit tap URL is required because this project does not use a separate `homebrew-athenz-user-cert` tap repository.

## List of Distributions

### Docker(OCI) Image

[athenz-user-cert](https://github.com/users/ctyano/packages/container/package/athenz-user-cert)

### Executable binaries

https://github.com/ctyano/athenz-user-cert/releases

## How to build

```
make
```

## Configuration

The CLI can read optional YAML configuration from `$HOME/.athenz/config.yaml`.
Set `ATHENZ_CONFIG_PATH` to use another file.

Values are applied in this order:

```
command line flags > environment variables > config.yaml > build-time defaults
```

Example:

```yaml
signer:
  name: zts

endpoint: https://zts.example.com/zts/v1/usercert
ca_endpoint: https://zts.example.com/zts/v1/ca
signer_tls_ca_path: /usr/local/etc/athenz/zts-server-ca.pem

oidc:
  issuer: https://issuer.example.com
  client_id: athenz-user-cert
  scopes: openid email profile
  listen_address: :8080
  username_claim: email

zts:
  timeout: 10
```

Common environment variable overrides include `ATHENZ_API_URL`,
`ATHENZ_CA_ENDPOINT`, `ATHENZ_SIGNER_TLS_CA_PATH`, `ATHENZ_OIDC_ISSUER`, and
`ATHENZ_ZTS_SIGN_URL`.

Use `-oidc-issuer https://issuer.example.com` to override the OIDC issuer for a
single CLI execution.
