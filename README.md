# ITP (Identity Translation Proxy)

[![Go Report Card](https://goreportcard.com/badge/github.com/taemon1337/itp)](https://goreportcard.com/report/github.com/taemon1337/itp)
[![GoDoc](https://godoc.org/github.com/taemon1337/itp?status.svg)](https://godoc.org/github.com/taemon1337/itp)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

ITP is a high-performance mTLS proxy that translates identities between different security domains. It enables secure communication between services by handling certificate-based authentication and identity mapping.

## Features

- **mTLS Support**: Full mutual TLS authentication for both client and server connections
- **Identity Translation**: Map certificates between different security domains based on various certificate fields
- **Flexible Routing**: Multiple routing strategies including DNS-based, static, path-based, and pattern-based routing
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

## CLI Configuration

### Required Flags
| Flag | Description | Default |
|------|-------------|---------||
| `--server-name` | Server name for the proxy | Required |
| `--external-domain` | External domain for connections | Required |
| `--internal-domain` | Internal domain for connections | Required |

### Network Configuration
| Flag | Description | Default |
|------|-------------|---------||
| `--listen` | Address to listen on | `:8443` |
| `--echo-name` | Name for the echo server | `echo.<internal-domain>` |
| `--echo-addr` | Address for the echo server | `:8444` |
| `--routes` | Comma-separated list of routes (e.g., `localhost=echo,app=app.internal`) | `""` |

### TLS Configuration
| Flag | Description | Default |
|------|-------------|---------|
| `--cert` | Path to certificate file | `""` |
| `--key` | Path to private key file | `""` |
| `--ca` | Path to CA certificate file | `""` |

### Security Configuration
| Flag | Description | Default |
|------|-------------|---------|
| `--allow-unknown-certs` | Allow unknown client certificates | `false` |
| `--route-via-dns` | Enable DNS-based routing | `false` |
| `--auto-map-cn` | Automatically map CommonName | `true` |

### Header Injection
| Flag | Description | Default |
|------|-------------|---------|
| `--inject-headers-upstream` | Inject headers upstream | `true` |
| `--inject-headers-downstream` | Inject headers downstream | `false` |
| `--inject-header` | Header template (e.g., `localhost=X-User={{.CommonName}}`) | `""` |
| `--add-role` | Role mapping (e.g., `cn=admin=admin-role`) | `""` |
| `--add-auth` | Auth mapping (e.g., `cn=*=read,write`) | `""` |
| `--server-name` | Server name for TLS connection | `proxy.test` |
| `--server-san` | Additional DNS names for server certificate (comma-separated) | `""` |
| `--server-allow-unknown-client-certs` | Allow client certificates from unknown CAs | `false` |
| `--internal-domain` | Internal domain for inside/upstream connections | `internal.local` |
| `--external-domain` | External domain for incoming connections | `external.com` |

### Certificate Generation

When no certificate files are provided (`--cert`, `--key`, `--ca`), ITP will automatically generate certificates:
- Server certificate for external connections (proxy's public interface)
- Internal certificates for client authentication and upstream connections
- All certificates include appropriate SANs based on domains and server names

When certificate files are provided:
- Uses the specified certificate files for both server and client connections
- CA certificate is required for client certificate verification
- Certificate must be valid for the specified `--server-name`

### Template Functions

When injecting headers, you can use these template functions:

| Function | Description | Example |
|----------|-------------|---------||
| `join` | Join slice with custom separator | `{{ .Groups \| join "; " }}` |
| `comma` | Join slice with commas | `{{ .Groups \| comma }}` |
| `space` | Join slice with spaces | `{{ .Groups \| space }}` |

### Echo Server Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `--echo` | Name for the echo upstream | `""` |
| `--echo-addr` | Address for echo upstream server | `:8444` |
| `--echo-san` | Additional DNS names for echo server certificate | `""` |

### Routing Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `--route` | Static routes (format: src=dest[,src=dest,...]), path-based routes (format: src/path=dest/path), or TLS-preserving routes (format: src=tls://dest) | `""` |
| `--route-via-dns` | Allow routing via DNS | `false` |
| `--map-auto` | Automatically map client CN to upstream CN | `false` |

#### Path-Based Routing

ITP supports path-based routing with prefix matching and path stripping:

```bash
# Route with path prefix replacement
itp --route "app.example.com/api=backend.cluster.local/v1"
# /api/users -> /v1/users

# Route with path stripping
itp --route "app.example.com/api=backend.cluster.local"
# /api/users -> /users

# Multiple path-based routes
itp --route "app.example.com/api=backend.cluster.local/v1,app.example.com/web=frontend.cluster.local"
```

Path-based routing features:
- Prefix matching for flexible path routing
- Optional path stripping when destination has no path
- Compatible with existing routing strategies
- Preserves unmatched paths in requests

#### TLS Verification Preservation

When routing to external services that have their own TLS certificates, you can preserve the original hostname for TLS verification:

```bash
# Route to external API with its own TLS certificate
itp --route "api.internal.com=tls://api.external.com:8443"

# Combine with path-based routing
itp --route "api.internal.com/v2=tls://api.external.com:8443/v1"
```

This is useful when:
- The destination uses its own TLS certificates (not provided by the proxy)
- The destination's certificate doesn't include the internal domain names
- You need to maintain end-to-end TLS verification while still using the proxy's routing capabilities

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