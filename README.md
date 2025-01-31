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

Start the proxy with automatic certificate generation and routing:
```bash
itp --server-cert auto \
    --server-name proxy.example.com \
    --server-san "proxy.internal,proxy.dev" \
    --map-auto \
    --route "app.cluster.com=app.default.svc.cluster.local"
```

## Configuration

### TLS Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `--server-cert` | Server certificate file or 'auto' for auto-generated | `auto` |
| `--server-key` | Server key file or 'auto' for auto-generated | `auto` |
| `--server-ca` | CA certificate file for server cert (only used with auto-generated certs) | |
| `--server-name` | Server name for TLS connection | |
| `--server-san` | Additional DNS names for server certificate (comma-separated) | |
| `--server-allow-unknown-client-certs` | Allow client certificates from unknown CAs | `false` |
| `--internal-domain` | Internal domain for inside/upstream connections | `cluster.local` |
| `--external-domain` | External domain for incoming connections | |

### Echo Server Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `--echo` | Name for the echo upstream (e.g. 'echo' to use in --route) | |
| `--echo-addr` | Address for echo upstream server | `:8444` |
| `--echo-san` | Additional DNS names for echo server certificate | |

### Identity Translation

| Option | Description | Example |
|--------|-------------|---------|
| `--map-auto` | Automatically map client CN to upstream CN | `--map-auto` |
| `--map-common-name` | Map common names | `--map-common-name "external.user=internal.user"` |
| `--map-organization` | Map organizations | `--map-organization "ExternalOrg=InternalTeam"` |
| `--map-organization-unit` | Map org units | `--map-organization-unit "ExternalOU=InternalOU"` |
| `--add-role` | Add roles based on cert fields | `--add-role "cn=admin@example.com=admin"` |
| `--add-auth` | Add auth values based on cert fields | `--add-auth "org=engineering=read,write"` |

### Header Injection

| Option | Description | Default |
|--------|-------------|---------|
| `--inject-header` | Inject headers using templates | See examples below |
| `--inject-headers-upstream` | Inject headers into upstream requests | `true` |
| `--inject-headers-downstream` | Inject headers into downstream responses | `false` |

Example header template:
```bash
--inject-header 'backend=X-User=USER:{{.CommonName}};{{range .Groups}}ROLE:{{.}}{{end}}'
```

Available template variables:
- `{{.CommonName}}` - Certificate common name
- `{{.Organization}}` - Organization names
- `{{.OrganizationalUnit}}` - Organizational unit names
- `{{.Groups}}` - Group names
- `{{.Roles}}` - Role names
- `{{.Auths}}` - Auth values

### Routing Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `--route` | Static routes (src=dest[,src=dest,...]) | |
| `--route-via-dns` | Allow routing via DNS | `false` |

### Other Options

| Option | Description | Default |
|--------|-------------|---------|
| `--addr` | Address to listen on | `:8443` |
| `--cert-store` | Certificate store type (k8s or auto) | `auto` |
| `--config` | Path to YAML configuration file | |

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