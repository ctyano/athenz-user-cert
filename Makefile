ifeq ($(APP_NAME),)
APP_NAME := athenz-user-cert
endif

ifeq ($(BINARY_NAME),)
BINARY_NAME := athenzusercert
endif

ifeq ($(APP_REPO_OWNER),)
APP_REPO_OWNER := ctyano
endif
ifeq ($(APP_REPO_DOMAIN),)
APP_REPO_DOMAIN := github.com
endif
ifeq ($(APP_REPO_URL),)
APP_REPO_URL := $(APP_REPO_DOMAIN)/$(APP_REPO_OWNER)/$(APP_NAME)
endif

LDFLAGS :=
ifneq ($(VERSION),)
LDFLAGS_ARGS += -X 'main.VERSION=$(VERSION)'
else
LDFLAGS_ARGS += -X 'main.VERSION=$(shell git rev-parse --short HEAD)'
endif
ifneq ($(BUILD_DATE),)
LDFLAGS_ARGS += -X 'main.BUILD_DATE=$(BUILD_DATE)'
else
LDFLAGS_ARGS += -X 'main.BUILD_DATE=$(shell date '+%Y-%m-%dT%H:%M:%S%Z%z')'
endif
ifneq ($(DEFAULT_APP_NAME),)
LDFLAGS_ARGS += -X 'main.DEFAULT_APP_NAME=$(DEFAULT_APP_NAME)'
else
LDFLAGS_ARGS += -X 'main.DEFAULT_APP_NAME=athenzusercert'
endif
ifneq ($(DEFAULT_SIGNER_NAME),)
LDFLAGS_ARGS += -X 'main.DEFAULT_SIGNER_NAME=$(DEFAULT_SIGNER_NAME)'
else
LDFLAGS_ARGS += -X 'main.DEFAULT_SIGNER_NAME=zts'
endif
ifneq ($(DEFAULT_OIDC_CLIENT_ID),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_CLIENT_ID=$(DEFAULT_OIDC_CLIENT_ID)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_CLIENT_ID=athenz-user-cert'
endif
ifneq ($(DEFAULT_OIDC_CLIENT_SECRET),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_CLIENT_SECRET=$(DEFAULT_OIDC_CLIENT_SECRET)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_CLIENT_SECRET=athenz-user-cert'
endif
ifneq ($(DEFAULT_OIDC_ISSUER),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_ISSUER=$(DEFAULT_OIDC_ISSUER)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_ISSUER=http://127.0.0.1:5556/dex'
endif
ifneq ($(DEFAULT_OIDC_LISTEN_ADDRESS),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_LISTEN_ADDRESS=$(DEFAULT_OIDC_LISTEN_ADDRESS)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_LISTEN_ADDRESS=":8080"'
endif
ifneq ($(DEFAULT_OIDC_SCOPES),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_SCOPES=$(DEFAULT_OIDC_SCOPES)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_SCOPES="openid\ email\ profile"'
endif
ifneq ($(DEFAULT_OIDC_ACCESS_TOKEN_PATH),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_ACCESS_TOKEN_PATH=$(DEFAULT_OIDC_ACCESS_TOKEN_PATH)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_ACCESS_TOKEN_PATH=.athenz/.accesstoken'
endif
ifneq ($(DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM=$(DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM=name'
endif
ifneq ($(DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM=$(DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_ATHENZ_EXTERNAL_ID_CLAIM=name'
endif

ifneq ($(DEFAULT_X509_USERKEY_PATH),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_X509_USERKEY_PATH=$(DEFAULT_X509_USERKEY_PATH)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_X509_USERKEY_PATH=/.athenz/user.key.pem'
endif
ifneq ($(DEFAULT_KEY_ALGORITHM),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_KEY_ALGORITHM=$(DEFAULT_KEY_ALGORITHM)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_KEY_ALGORITHM=RSA'
endif
ifneq ($(DEFAULT_X509_USERCERT_PATH),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_X509_USERCERT_PATH=$(DEFAULT_X509_USERCERT_PATH)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_X509_USERCERT_PATH=/.athenz/user.cert.pem'
endif
ifneq ($(DEFAULT_X509_CACERT_PATH),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_X509_CACERT_PATH=$(DEFAULT_X509_CACERT_PATH)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_X509_CACERT_PATH=/.athenz/ca.cert.pem'
endif
ifneq ($(DEFAULT_ATHENZ_CN_MODE),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_ATHENZ_CN_MODE=$(DEFAULT_ATHENZ_CN_MODE)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_ATHENZ_CN_MODE=user'
endif
ifneq ($(DEFAULT_ATHENZ_USER_DOMAIN),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_ATHENZ_USER_DOMAIN=$(DEFAULT_ATHENZ_USER_DOMAIN)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_ATHENZ_USER_DOMAIN=user'
endif
ifneq ($(DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN=$(DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/certificate.DEFAULT_ATHENZ_EXTERNAL_ID_DOMAIN='
endif

ifneq ($(DEFAULT_SIGNER_TLS_CA_PATH),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_TLS_CA_PATH=$(DEFAULT_SIGNER_TLS_CA_PATH)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_TLS_CA_PATH=.athenz/ca.cert.pem'
endif

ifneq ($(DEFAULT_SIGNER_CRYPKI_SIGN_URL),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL=$(DEFAULT_SIGNER_CRYPKI_SIGN_URL)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL=http://localhost:10000/v3/sig/x509-cert/keys/x509-key'
endif
ifneq ($(DEFAULT_SIGNER_CRYPKI_CA_URL),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CRYPKI_CA_URL=$(DEFAULT_SIGNER_CRYPKI_CA_URL)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CRYPKI_CA_URL=http://localhost:10000/v3/sig/x509-cert/keys/x509-key'
endif
ifneq ($(DEFAULT_SIGNER_CRYPKI_VALIDITY),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CRYPKI_VALIDITY=$(DEFAULT_SIGNER_CRYPKI_VALIDITY)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CRYPKI_VALIDITY=2592000' # 30 * 24 * 60 * 60 seconds
endif
ifneq ($(DEFAULT_SIGNER_CRYPKI_IDENTIFIER),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CRYPKI_IDENTIFIER=$(DEFAULT_SIGNER_CRYPKI_IDENTIFIER)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CRYPKI_IDENTIFIER=athenz'
endif
ifneq ($(DEFAULT_SIGNER_CRYPKI_TIMEOUT),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CRYPKI_TIMEOUT=$(DEFAULT_SIGNER_CRYPKI_TIMEOUT)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CRYPKI_TIMEOUT=10' # seconds
endif

ifneq ($(DEFAULT_SIGNER_CFSSL_SIGN_URL),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CFSSL_SIGN_URL=$(DEFAULT_SIGNER_CFSSL_SIGN_URL)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CFSSL_SIGN_URL=http://localhost:10000/api/v1/cfssl/sign'
endif
ifneq ($(DEFAULT_SIGNER_CFSSL_CA_URL),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CFSSL_CA_URL=$(DEFAULT_SIGNER_CFSSL_CA_URL)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CFSSL_CA_URL=http://localhost:10000/api/v1/cfssl/info'
endif
ifneq ($(DEFAULT_SIGNER_CFSSL_TIMEOUT),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CFSSL_TIMEOUT=$(DEFAULT_SIGNER_CFSSL_TIMEOUT)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_CFSSL_TIMEOUT=10'
endif

ifneq ($(DEFAULT_SIGNER_ZTS_SIGN_URL),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_ZTS_SIGN_URL=$(DEFAULT_SIGNER_ZTS_SIGN_URL)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_ZTS_SIGN_URL=https://127.0.0.1:4443/zts/v1/usercert'
endif
ifneq ($(DEFAULT_SIGNER_ZTS_CA_URL),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_ZTS_CA_URL=$(DEFAULT_SIGNER_ZTS_CA_URL)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_ZTS_CA_URL='
endif
ifneq ($(DEFAULT_SIGNER_ZTS_TIMEOUT),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_ZTS_TIMEOUT=$(DEFAULT_SIGNER_ZTS_TIMEOUT)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_ZTS_TIMEOUT=10'
endif

ifneq ($(DEFAULT_SIGNER_VAULT_JWT_ROLE),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_VAULT_JWT_ROLE=$(DEFAULT_SIGNER_VAULT_JWT_ROLE)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_VAULT_JWT_ROLE=jwt'
endif
ifneq ($(DEFAULT_SIGNER_VAULT_PKI_NAME),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_VAULT_PKI_NAME=$(DEFAULT_SIGNER_VAULT_PKI_NAME)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_VAULT_PKI_NAME=rootca'
endif
ifneq ($(DEFAULT_SIGNER_VAULT_PKI_ROLE),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_VAULT_PKI_ROLE=$(DEFAULT_SIGNER_VAULT_PKI_ROLE)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_VAULT_PKI_ROLE=issuers'
endif
ifneq ($(DEFAULT_SIGNER_VAULT_SIGN_URL),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_VAULT_SIGN_URL=$(DEFAULT_SIGNER_VAULT_SIGN_URL)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/signer.DEFAULT_SIGNER_VAULT_SIGN_URL=http://localhost:10000/v1/rootca/sign/issuers'
ifneq ($(LDFLAGS_ARGS),)
LDFLAGS += -ldflags "$(LDFLAGS_ARGS)"
endif

ifeq ($(GOOS),)
GOOS := $(shell go env GOOS))
endif
ifeq ($(GOARCH),)
GOARCH := $(shell go env GOARCH))
endif

.PHONY: go-build go-test go-clean

go-build:
	@echo "Building $(BINARY_NAME)..."
	go mod tidy
	CGO_ENABLED=1 go build $(LDFLAGS) -o $(GOPATH)/bin/$(BINARY_NAME) cmd/*.go

go-cross-build:
	@echo "Cross Building $(BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	go mod tidy
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=1 go build $(LDFLAGS) -o $(GOPATH)/bin/$(GOOS)_$(GOARCH)/$(BINARY_NAME) cmd/*.go

go-test:
	@echo "Testing..."
	go test -v -failfast -timeout 1m -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

go-clean:
	rm -rf $(shell pwd)/bin || true
	chmod -R a+w pkg/ || true
	rm -rf $(shell pwd)/pkg || true



ifeq ($(DOCKER_TAG),)
DOCKER_TAG := :latest
endif
ifneq ($(VERSION),)
DOCKER_TAG := :v$(VERSION)
endif

ifeq ($(PATCH),)
PATCH := true
endif

ifeq ($(PUSH),)
PUSH := true
endif
ifeq ($(PUSH),true)
PUSH_OPTION := --push
endif

BUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
VCS_REF=$(shell git rev-parse --short HEAD)

ifeq ($(XPLATFORMS),)
XPLATFORMS := linux/amd64,linux/arm64
endif
XPLATFORM_ARGS := --platform=$(XPLATFORMS)

BUILD_ARG := --build-arg 'BUILD_DATE=$(BUILD_DATE)' --build-arg 'VCS_REF=$(VCS_REF)' --build-arg 'VERSION=$(VERSION)'

ifeq ($(DOCKER_REGISTRY_OWNER),)
DOCKER_REGISTRY_OWNER=ctyano
endif

ifeq ($(DOCKER_REGISTRY),)
DOCKER_REGISTRY=ghcr.io/$(DOCKER_REGISTRY_OWNER)/
endif

ifeq ($(DOCKER_CACHE),)
DOCKER_CACHE=false
endif

.SILENT: version

build:
	IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME)$(DOCKER_TAG); \
	LATEST_IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME):latest; \
	DOCKERFILE_PATH=./Dockerfile; \
	test $(DOCKER_CACHE) && DOCKER_CACHE_OPTION="--cache-from $$IMAGE_NAME"; \
	docker build $(BUILD_ARG) $$DOCKER_CACHE_OPTION -t $$IMAGE_NAME -t $$LATEST_IMAGE_NAME -f $$DOCKERFILE_PATH .

buildx:
	IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME)$(DOCKER_TAG); \
	LATEST_IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME):latest; \
	DOCKERFILE_PATH=./Dockerfile; \
	DOCKER_BUILDKIT=1 docker buildx build $(BUILD_ARG) $(XPLATFORM_ARGS) $(PUSH_OPTION) --cache-from $$IMAGE_NAME -t $$IMAGE_NAME -t $$LATEST_IMAGE_NAME -f $$DOCKERFILE_PATH .

mirror-amd64-images:
	IMAGE=$(APP_NAME); docker pull --platform linux/amd64 $(DOCKER_REGISTRY)$$IMAGE:latest && docker tag $(DOCKER_REGISTRY)$$IMAGE:latest docker.io/tatyano/$$IMAGE:latest && docker push docker.io/tatyano/$$IMAGE:latest

install-golang:
	which go \
|| (curl -sf https://webi.sh/golang | sh \
&& ~/.local/bin/pathman add ~/.local/bin)

version:
	@echo "Version: $(VERSION)"
	@echo "Tag Version: v$(VERSION)"

install-pathman:
	test -e ~/.local/bin/pathman \
|| curl -sf https://webi.sh/pathman | sh

install-jq: install-pathman
	which jq \
|| (curl -sf https://webi.sh/jq | sh \
&& ~/.local/bin/pathman add ~/.local/bin)

install-yq: install-pathman
	which yq \
|| (curl -sf https://webi.sh/yq | sh \
&& ~/.local/bin/pathman add ~/.local/bin)

install-step: install-pathman
	which step \
|| (STEP_VERSION=$$(curl -sf https://api.github.com/repos/smallstep/cli/releases | jq -r .[].tag_name | grep -E '^v[0-9]*.[0-9]*.[0-9]*$$' | head -n1 | sed -e 's/.*v\([0-9]*.[0-9]*.[0-9]*\).*/\1/g') \
; curl -fL "https://github.com/smallstep/cli/releases/download/v$${STEP_VERSION}/step_$(GOOS)_$${STEP_VERSION}_$(GOARCH).tar.gz" | tar -xz -C ~/.local/bin/ \
&& ln -sf ~/.local/bin/step_$${STEP_VERSION}/bin/step ~/.local/bin/step \
&& ~/.local/bin/pathman add ~/.local/bin)

install-kustomize: install-pathman
	which kustomize \
|| (cd ~/.local/bin \
&& curl "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash \
&& ~/.local/bin/pathman add ~/.local/bin)

install-parsers: install-jq install-yq install-step
