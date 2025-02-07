# ITP (Identity Translation Proxy)

[![Go Report Card](https://goreportcard.com/badge/github.com/taemon1337/itp)](https://goreportcard.com/report/github.com/taemon1337/itp)
[![GoDoc](https://godoc.org/github.com/taemon1337/itp?status.svg)](https://godoc.org/github.com/taemon1337/itp)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

ITP is a high-performance mTLS proxy that translates identities between different security domains. It enables secure communication between services by handling certificate-based authentication and identity mapping.

## Features

- **mTLS Support**: Full mutual TLS authentication for both client and server connections
- **Identity Translation**: Map certificates between different security domains based on various certificate fields
- **Flexible Routing**: Multiple routing strategies including DNS-based, static, and pattern-based routing
- **Dynamic Certificates**: Automatic certificate selection based on client certificate attributes
- **Real-time Echo Server**: Built-in echo server for debugging TLS connections
- **High Performance**: Written in Go for optimal performance and minimal resource usage
- **Header Injection**: Inject custom headers based on certificate attributes
- **Role-based Access**: Add roles and auth values based on certificate fields

## How It Works

```
External Domain                    ITP Proxy                     Internal Domain
(external.com)                                                  (cluster.local)
                                ┌──────────────┐
                                │   Identity   │
                                │ Translation  │
                                │    Proxy     │
                                └──────────────┘
    ┌──────┐     1. mTLS          ┌──────┐     3. mTLS          ┌──────────┐
    │Client├────Connection────────┤ ITP  ├─────Connection───────┤ Backend  │
    └──────┘                      └──────┘                      └──────────┘
      │                              │                               │
      │                              │                               │
      │   CN: user@external.com      │     CN: user                  │
      │   O: ExternalOrg             │     O: Internal               │
      │   OU: DevTeam                │     OU: Engineering           │
      │                              │                               │
      │                        2. Translation                        │
      │                        ───────────────►                      │
      │                        - Map CN, O, OU                       │
      │                        - Add Roles                           │
      │                        - Add Auth                            │
      │                        - Inject Headers                      │
      │                                                              │
      │                                                              │
      │                     4. Headers Injected                      │
      │                        X-User: user                          │
      │                        X-Roles: developer                    │
      │                        X-Auth: read,write                    │
```

## Installation

### Using Go

```bash
go install github.com/taemon1337/itp@latest
```

### Using Docker

ITP provides two Docker image variants:

1. **Distroless variant** (Recommended for Production)
   ```bash
   docker pull taemon1337/itp:latest-distroless
   ```
   - Minimal attack surface
   - Smaller image size
   - Based on Google's distroless base image

2. **Alpine variant** (Recommended for Development)
   ```bash
   docker pull taemon1337/itp:latest-alpine
   ```
   - Includes debugging tools
   - Shell access available

### Building from Source

```bash
git clone https://github.com/taemon1337/itp.git
cd itp
make build      # Build binary
make test       # Run tests
make docker-build  # Build both Docker variants
```

## Quick Start

Start the proxy with automatic certificate generation:
```bash
itp --server-name proxy.example.com \
    --server-san "proxy.internal,proxy.dev" \
    --map-auto \
    --route "app.cluster.com=app.default.svc.cluster.local"
```

Or use your own certificates:
```bash
itp --server-cert /path/to/cert.pem \
    --server-key /path/to/key.pem \
    --server-ca /path/to/ca.pem \
    --server-name proxy.example.com \
    --map-auto \
    --route "app.cluster.com=app.default.svc.cluster.local"
```

## Configuration

### TLS Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `--server-cert` | Server certificate file (empty for auto-generated) | `""` |
| `--server-key` | Server key file (empty for auto-generated) | `""` |
| `--server-ca` | CA certificate file for server cert | `""` |
| `--server-name` | Server name for TLS connection | `proxy.test` |
| `--server-san` | Additional DNS names for server certificate (comma-separated) | `""` |
| `--server-allow-unknown-client-certs` | Allow client certificates from unknown CAs | `false` |
| `--internal-domain` | Internal domain for inside/upstream connections | `internal.local` |
| `--external-domain` | External domain for incoming connections | `external.com` |

### Certificate Generation

When `--server-cert` is empty, ITP will automatically generate certificates:
- Server certificate for external connections (proxy's public interface)
- Internal certificates for client authentication and upstream connections
- All certificates include appropriate SANs based on domains and server names

When `--server-cert` is provided:
- Uses the specified certificate files for both server and client connections
- CA certificate is required for client certificate verification
- Certificate must be valid for the specified `--server-name`

### Echo Server Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `--echo` | Name for the echo upstream | `""` |
| `--echo-addr` | Address for echo upstream server | `:8444` |
| `--echo-san` | Additional DNS names for echo server certificate | `""` |

### Routing Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `--route` | Static routes (format: src=dest[,src=dest,...]) | `""` |
| `--route-via-dns` | Allow routing via DNS | `false` |
| `--map-auto` | Automatically map client CN to upstream CN | `false` |

### Header Injection

| Flag | Description | Default |
|------|-------------|---------|
| `--inject-header` | Inject headers (format: upstream=name=template[,...]) | `""` |
| `--inject-headers-upstream` | Inject headers into upstream requests | `true` |
| `--inject-headers-downstream` | Inject headers into downstream responses | `false` |

### Identity Mapping

| Flag | Description | Default |
|------|-------------|---------|
| `--add-role` | Add roles (format: field=value=role1,role2,...) | `""` |
| `--add-auth` | Add auth values (format: field=value=auth1,auth2,...) | `""` |
| `--config` | Path to YAML configuration file | `""` |

## Project Structure

```
.
├── cmd/                  # Command-line interface
├── pkg/                  # Core packages
│   ├── certstore/       # Certificate management
│   ├── echo/            # Echo server implementation
│   ├── identity/        # Identity translation
│   ├── logger/          # Logging utilities
│   ├── proxy/           # Core proxy functionality
│   └── router/          # Request routing
└── examples/            # Example configurations
```

## Identity Translation Proxy (ITP)

A TLS proxy that translates client identities between different domains, with support for header injection and flexible routing.

## Features

- TLS termination with client certificate authentication
- Automatic certificate generation for server and clients
- Identity translation between external and internal domains
- Header injection based on client certificate attributes
- Flexible routing with DNS support
- Echo server for testing and development

## Installation

```bash
go install github.com/taemon1337/itp@latest
```

## Usage

### Basic Usage

The minimum required configuration needs a server name, external domain, and internal domain:

```bash
itp --server-name proxy.example.com \
    --external-domain example.com \
    --internal-domain internal.local
```

### Configuration Options

#### Required Flags
- `--server-name`: Server name for the proxy (e.g., proxy.example.com)
- `--external-domain`: External domain for connections (e.g., external.com)
- `--internal-domain`: Internal domain for connections (e.g., internal.local)

#### Optional Flags
- `--listen`: Address to listen on (default: ":8443")
- `--echo-name`: Name for the echo server (defaults to echo.<internal-domain>)
- `--echo-addr`: Address for the echo server (default: ":8444")

#### Certificate Configuration
- `--cert`: Path to certificate file
- `--key`: Path to private key file
- `--ca`: Path to CA certificate file

#### Security Options
- `--allow-unknown-certs`: Allow unknown client certificates
- `--route-via-dns`: Enable DNS-based routing
- `--auto-map-cn`: Automatically map CommonName (default: true)

#### Header Injection
- `--inject-headers-upstream`: Inject headers upstream (default: true)
- `--inject-headers-downstream`: Inject headers downstream (default: false)

### Examples

#### Basic Proxy with Echo Server

```bash
itp --server-name proxy.example.com \
    --external-domain example.com \
    --internal-domain internal.local \
    --echo-name echo
```

#### Custom Certificates

```bash
itp --server-name proxy.example.com \
    --external-domain example.com \
    --internal-domain internal.local \
    --cert /path/to/cert.pem \
    --key /path/to/key.pem \
    --ca /path/to/ca.pem
```

#### Development Mode

```bash
itp --server-name proxy.test \
    --external-domain test.com \
    --internal-domain local \
    --allow-unknown-certs \
    --echo-name echo \
    --route-via-dns
```

## Development

### Building from Source

```bash
git clone https://github.com/taemon1337/itp.git
cd itp
go build
```

### Running Tests

```bash
go test ./...
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.