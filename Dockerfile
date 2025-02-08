# syntax=docker/dockerfile:1.4
# Build stage
FROM golang:1.23-alpine AS builder

# Build arguments
ARG VERSION=dev
ARG COMMIT_SHA

# Install build dependencies early for better caching
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy source code
COPY . .

# Build the application with version info
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s \
    -X main.version=${VERSION} \
    -X main.commitSha=${COMMIT_SHA}" \
    -o /app/itp

# Final stage using distroless (smaller, more secure)
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy the binary from builder
COPY --from=builder --chown=nonroot:nonroot /app/itp .

# Expose the default port
EXPOSE 8443

# Set up healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/itp", "health"] || exit 1

# Use nonroot user
USER nonroot:nonroot

# Run the application
ENTRYPOINT ["/app/itp"]