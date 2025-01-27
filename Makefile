# Build variables
BINARY_NAME=itp
DOCKER_IMAGE=itp
VERSION?=1.0.0
DOCKER_BUILD_IMAGE=golang:1.21-alpine
DOCKER_LINT_IMAGE=golangci/golangci-lint:v1.55.2

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help
help: ## Display this help message
	@echo "Usage:"
	@grep -h "##" $(MAKEFILE_LIST) | grep -v grep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY: clean
clean: ## Clean build artifacts
	docker run --rm -v $(PWD):/app -w /app $(DOCKER_BUILD_IMAGE) sh -c "rm -f $(BINARY_NAME)"

.PHONY: deps
deps: ## Download dependencies
	docker run --rm -v $(PWD):/app -w /app $(DOCKER_BUILD_IMAGE) sh -c "go mod download"

.PHONY: tidy
tidy: ## Tidy go modules
	docker run --rm -v $(PWD):/app -w /app $(DOCKER_BUILD_IMAGE) sh -c "go mod tidy"

.PHONY: fmt
fmt: ## Run go fmt
	docker run --rm -v $(PWD):/app -w /app $(DOCKER_BUILD_IMAGE) sh -c "go fmt ./..."

.PHONY: vet
vet: ## Run go vet
	docker run --rm -v $(PWD):/app -w /app $(DOCKER_BUILD_IMAGE) sh -c "go vet ./..."

.PHONY: lint
lint: ## Run golangci-lint
	docker run --rm -v $(PWD):/app -w /app $(DOCKER_LINT_IMAGE) golangci-lint run --timeout 5m

.PHONY: test
test: ## Run tests
	docker run --rm -v $(PWD):/app -w /app $(DOCKER_BUILD_IMAGE) sh -c "go test -v -race -coverprofile=coverage.out ./..."

.PHONY: coverage
coverage: test ## Generate test coverage report
	docker run --rm -v $(PWD):/app -w /app $(DOCKER_BUILD_IMAGE) sh -c "go tool cover -html=coverage.out -o coverage.html"

.PHONY: build
build: ## Build binary using Docker
	docker run --rm -v $(PWD):/app -w /app $(DOCKER_BUILD_IMAGE) sh -c "\
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) -ldflags='-w -s -X main.version=$(VERSION)' ."

.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE):$(VERSION) .
	docker tag $(DOCKER_IMAGE):$(VERSION) $(DOCKER_IMAGE):latest

.PHONY: docker-push
docker-push: ## Push Docker image
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest

.PHONY: run
run: ## Run the application in Docker
	docker-compose up --build

.PHONY: dev
dev: ## Run the application in development mode with live reload
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up --build

.PHONY: generate-certs
generate-certs: ## Generate development certificates
	docker run --rm -v $(PWD):/app -w /app $(DOCKER_BUILD_IMAGE) sh -c "\
		apk add --no-cache openssl && \
		openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost' && \
		cp server.crt ca.crt"

.PHONY: all
all: clean deps fmt vet lint test build ## Run all tasks (clean, deps, fmt, vet, lint, test, build)

.PHONY: ci
ci: deps fmt vet lint test build ## Run CI tasks (deps, fmt, vet, lint, test, build)