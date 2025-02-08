# Build variables
BINARY_NAME=itp
DOCKER_IMAGE=taemon1337/itp
VERSION?=1.0.0
BUILD_DATE?=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
COMMIT_SHA?=$(shell git rev-parse --short HEAD)
GO_DOCKER_IMAGE=golang:1.23-alpine

# Docker BuildKit settings
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Docker run command with common options
DOCKER_GO_RUN=docker run --rm \
	-v $(PWD):/app \
	-v go-cache:/root/.cache/go-build \
	-v go-mod-cache:/go/pkg/mod \
	-w /app \
	$(GO_DOCKER_IMAGE)

SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help
help: ## Display this help message
	@echo "Usage:"
	@grep -h "##" $(MAKEFILE_LIST) | grep -v grep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY: clean
clean: ## Clean build artifacts
	rm -f $(BINARY_NAME)
	rm -f *.crt *.key

.PHONY: deps
deps: ## Download dependencies
	$(DOCKER_GO_RUN) go mod download

.PHONY: tidy
tidy: ## Tidy go modules
	$(DOCKER_GO_RUN) go mod tidy

.PHONY: fmt
fmt: ## Run go fmt
	$(DOCKER_GO_RUN) go fmt ./...

.PHONY: vet
vet: ## Run go vet
	$(DOCKER_GO_RUN) go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	docker run --rm \
		-v $(PWD):/app \
		-v go-cache:/root/.cache/go-build \
		-v go-mod-cache:/go/pkg/mod \
		-w /app \
		golangci/golangci-lint:v1.63.4 golangci-lint run

.PHONY: test
test: ## Run tests
	$(DOCKER_GO_RUN) go test -v ./...

.PHONY: build
build: ## Build binary
	$(DOCKER_GO_RUN) go build \
		-ldflags="-w -s \
		-X main.version=${VERSION} \
		-X main.buildDate=${BUILD_DATE} \
		-X main.commitSha=${COMMIT_SHA}" \
		-o $(BINARY_NAME)

.PHONY: docker-build
docker-build: ## Build docker image
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg COMMIT_SHA=$(COMMIT_SHA) \
		-t $(DOCKER_IMAGE):$(VERSION) \
		-t $(DOCKER_IMAGE):latest .

.PHONY: docker-push
docker-push: ## Push docker image
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest

.PHONY: generate-certs
generate-certs: ## Generate development certificates
	docker run --rm \
		-v $(PWD):/app \
		-w /app \
		$(GO_DOCKER_IMAGE) sh -c "\
		apk add --no-cache openssl && \
		openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost' && \
		cp server.crt ca.crt"

.PHONY: all
all: clean deps fmt vet lint test build ## Run all build steps

.PHONY: docker-all
docker-all: all docker-build ## Build everything including docker image

.PHONY: echo
echo:
	docker run --rm \
	-p 8443:8443 \
	-v /etc/timezone:/etc/timezone:ro \
	-v /etc/localtime:/etc/localtime:ro \
	$(DOCKER_IMAGE):$(VERSION) \
		--server-name proxy \
		--internal-domain internal.com \
		--external-domain external.com \
		--echo-name echo \
		--allow-unknown-certs \
		--routes localhost=echo \
		--auto-map-cn \
		--external-domain external.com \
		--inject-header 'localhost=X-User=USER:{{.CommonName}};{{if .Roles}}{{range .Roles}}ROLE:{{.}}{{end}};{{if .Auths}}{{range .Auths}}AUTH:{{.}};{{end}}{{end}}{{end}}' \
		--inject-headers-upstream \
		--add-role 'cn=curler=echo-user' \
		--add-auth 'cn=*=read,write'

.PHONY: echobin
echobin:
	./$(BINARY_NAME) \
	--server-name proxy \
	--internal-domain internal.com \
	--external-domain external.com \
	--echo-name echo \
	--allow-unknown-certs \
	--routes localhost=echo \
	--auto-map-cn \
	--external-domain external.com \
	--inject-header 'localhost=X-User=USER:{{.CommonName}};{{if .Roles}}{{range .Roles}}ROLE:{{.}}{{end}};{{if .Auths}}{{range .Auths}}AUTH:{{.}};{{end}}{{end}}{{end}}' \
	--inject-headers-upstream \
	--add-role 'cn=curler=echo-user' \
	--add-auth 'cn=*=read,write'

# Create Docker volumes for caching if they don't exist
.PHONY: init
init: ## Initialize Docker volumes for caching
	docker volume create go-cache
	docker volume create go-mod-cache
