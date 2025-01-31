# Build stage
FROM golang:1.23-alpine AS builder

# Build arguments
ARG VERSION=dev
ARG BUILD_DATE
ARG COMMIT_SHA

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with version info
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s \
    -X main.version=${VERSION} \
    -X main.buildDate=${BUILD_DATE} \
    -X main.commitSha=${COMMIT_SHA}" \
    -o /app/itp

# Distroless final stage
FROM gcr.io/distroless/static-debian12:nonroot AS distroless

WORKDIR /app

# Copy the binary and certs from builder
COPY --from=builder --chown=nonroot:nonroot /app/itp .
COPY --from=builder --chown=nonroot:nonroot /app/*.crt /app/*.key ./

# Expose the default port
EXPOSE 8443

# Set up healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/itp", "health"] || exit 1

# Use nonroot user
USER nonroot:nonroot

# Run the application
ENTRYPOINT ["/app/itp"]

# Alpine final stage (as an alternative)
FROM alpine:3.19 AS alpine

WORKDIR /app

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Install minimal runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy the binary and certs from builder
COPY --from=builder --chown=appuser:appgroup /app/itp .
COPY --from=builder --chown=appuser:appgroup /app/*.crt /app/*.key ./

# Expose the default port
EXPOSE 8443

# Set up healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /app/itp health || exit 1

# Use non-root user
USER appuser

# Run the application
ENTRYPOINT ["/app/itp"]