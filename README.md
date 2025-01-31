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
      │                                                              │

Features:
• Secure mTLS on both sides
• Certificate field mapping (CN, O, OU)
• Role-based access control
• Header injection
• Domain translation
• Automatic routing
```

## Installation

### Using Go

```bash
go install github.com/taemon1337/itp@latest
```

### Using Docker

ITP provides two Docker image variants optimized for different use cases:

1. **Distroless variant** (Recommended for Production)
   ```bash
   docker pull taemon1337/itp:latest-distroless
   ```
   - Minimal attack surface
   - Smaller image size
   - Based on Google's distroless base image
   - No shell or debugging tools

2. **Alpine variant** (Recommended for Development/Debugging)
   ```bash
   docker pull taemon1337/itp:latest-alpine
   ```
   - Includes basic debugging tools
   - Shell access available
   - Based on Alpine Linux

#### Building Docker Images

Build both variants:
```bash
make docker-build
```

Build specific variant:
```bash
# Build distroless variant
make docker-build-distroless

# Build alpine variant
make docker-build-alpine
```

You can also specify version and other build arguments:
```bash
VERSION=2.0.0 make docker-build
```

### Building from Source

```bash
git clone https://github.com/taemon1337/itp.git
cd itp
make build
```

## Quick Start

1. Start the proxy with basic configuration:
```bash
itp --server-cert server.crt \
    --server-key server.key \
    --server-ca ca.crt \
    --addr :8443
```

2. Use automatic mapping and routing:
```bash
itp --server-cert server.crt \
    --server-key server.key \
    --server-ca ca.crt \
    --addr :8443 \
    --map-auto \
    --route "app.cluster.com=app.default.svc.cluster.local"
```

## Configuration

### Command Line Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `--addr` | Address for TLS proxy server to listen on | `:8443` |
| `--server-cert` | Server certificate file or 'auto' for auto-generated | `auto` |
| `--server-key` | Server key file or 'auto' for auto-generated | `auto` |
| `--server-ca` | CA certificate file for server cert (only used with auto-generated certs) | |
| `--server-allow-unknown-client-certs` | Allow client certificates from unknown CAs | `false` |
| `--map-auto` | Automatically map client CN to upstream CN | `false` |
| `--server-name` | If generating server certificates, use this server name for TLS connection | |
| `--internal-domain` | Internal domain for inside/upstream connections | `cluster.local` |
| `--external-domain` | External domain for incoming connections | |
| `--cert-store` | Certificate store type (k8s or auto) | `auto` |
| `--echo` | Name for the echo upstream (e.g. 'echo' to use in --route src=echo) | |
| `--echo-addr` | Address for echo upstream server | `:8444` |
| `--config` | Path to YAML configuration file for identity mappings and headers | |
| `--route` | Static routes in format src=dest[,src=dest,...] | |
| `--route-via-dns` | Allow routing to unspecified destinations via DNS | `false` |
| `--inject-header` | Inject headers in format upstream=name=template[,upstream=name=template,...] | |
| `--inject-headers-upstream` | Inject headers into upstream requests | `false` |
| `--inject-headers-downstream` | Inject headers into downstream responses | `false` |
| `--add-role` | Add roles in format field=value=role1,role2,... | |
| `--add-auth` | Add auth values in format field=value=auth1,auth2,... | |

The `--add-role` and `--add-auth` flags support these fields:
- `cn` - Common Name
- `org` - Organization
- `ou` - Organizational Unit
- `l` - Locality
- `c` - Country
- `st` - State

The value can be:
- An exact match (e.g., `cn=admin@example.com`)
- A wildcard `*` to match any value (e.g., `cn=*`)

Example:
```bash
# Add admin role to any certificate with CN=admin@example.com
--add-role "cn=admin@example.com=admin"

# Add read,write auths to all certificates (using wildcard)
--add-auth "cn=*=read,write"

# Add viewer role to all certificates in the engineering org
--add-role "org=engineering=viewer"
```

The `--inject-header` flag supports Go templates with these variables:
- `{{.CommonName}}` - Certificate common name
- `{{.Organization}}` - Organization names
- `{{.OrganizationalUnit}}` - Organizational unit names
- `{{.Groups}}` - Group names
- `{{.Roles}}` - Role names
- `{{.Auths}}` - Auth values

Example:
```bash
itp --inject-header 'backend=X-User=USER:{{.CommonName}};{{range .Groups}}ROLE:{{.}}{{end}}'
```

### YAML Configuration

For more complex setups, you can use a YAML configuration file:

```yaml
rules:
  - source: "cn"    # certificate field to match (cn, org, ou)
    match: "value"  # value to match
    roles: []       # roles to add
    groups: []      # groups to add
    auths: []       # auth values to add
    attributes: {}  # other attributes to set

headers:
  - upstream: "backend"  # upstream service name
    headers:            # headers to inject
      X-User: "value"
```

Use the configuration file with:
```bash
itp --config config.yaml
```

### Routing Options

ITP supports two routing modes in order of priority:

1. **Static Routes** (Highest Priority)
   ```bash
   --route app.cluster.com=app.default.svc.cluster.local
   ```

2. **DNS-based Routing** (Default)
   - Automatically routes based on SNI domain resolution

### Identity Translation

ITP provides a powerful identity translation system that works in two phases:

1. **Basic Identity Translation** (Phase 1)
   - When a client connects with a TLS certificate, ITP can either:
     a) Use explicit mappings to translate certificate fields to new values (using `--map-*` flags)
     b) Auto-map the certificate fields as-is when `--map-auto` is enabled and no explicit mappings exist
   
2. **Role, Group, and Auth Enhancement** (Phase 2)
   - After the basic translation, ITP can add roles, groups, and auth values based on the *translated* certificate fields
   - This happens through conditional mapping flags (`--add-role`, `--add-auth`)
   - The conditions are evaluated against the original certificate values

#### Direct Field Mapping (Phase 1)

Map certificate fields to internal identities using these options:

| Field | Command | Example |
|-------|---------|---------|
| Common Name | `--map-common-name` | `--map-common-name "external.user=internal.user"` |
| Organization | `--map-organization` | `--map-organization "ExternalOrg=InternalTeam"` |
| Org Unit | `--map-organization-unit` | `--map-organization-unit "ExternalOU=InternalOU"` |
| Country | `--map-country` | `--map-country "US=USA"` |
| State | `--map-state` | `--map-state "CA=California"` |
| Locality | `--map-locality` | `--map-locality "SanFrancisco=SF"` |

Auto-mapping can be enabled with `--map-auto`. When enabled and no explicit mappings match:
- All certificate fields are copied as-is to the internal certificate
- For example, if external cert has CN="user1", the internal cert will also have CN="user1"

#### Conditional Role/Group/Auth Injection (Phase 2)

Add roles, groups, and auth values to upstream certificates based on incoming certificate attributes:

| Command | Description | Example |
|---------|-------------|---------|
| `--add-role` | Add roles based on certificate field | `--add-role "cn=admin@example.com=admin,viewer"` |
| `--add-auth` | Add auth values based on certificate field | `--add-auth "cn=admin@example.com=read,write"` |

#### Header Templates

Headers can use Go templates with the following variables:
- `{{.CommonName}}` - the client cert CN
- `{{.Organization}}` - the client cert O
- `{{.OrganizationalUnit}}` - the client cert OU
- `{{.Roles}}` - array of roles
- `{{.Groups}}` - array of groups
- `{{.Auths}}` - array of auth values

Example complex header template:
```yaml
headers:
  - upstream: "backend"
    headers:
      X-User: "USER:{{.CommonName}};{{range .Groups}}ROLE:{{.}}{{end}};{{range .Auths}}AUTH:{{.}}{{end}}"
```

This would generate headers like:
```
X-User: USER:admin@example.com;ROLE:admins;ROLE:eng-team;AUTH:read;AUTH:write
```

### Inject HTTP headers

The upstream TLS client certificate will contain the internal user's groups and roles; however, many times the upstream service expects the user's groups and roles in HTTP headers.

To inject these headers, ITP supports both flexible templating and shortcuts for common cases:

#### Flexible Header Injection
Use `--inject-header` for full template control:

| Option | Description | Example |
|--------|-------------|---------|
| `--inject-header` | Inject custom headers using templates | `--inject-header "app.svc=X-Groups={{.Groups}},app.svc=X-Custom=static-value"` |

Available template variables:
- `.CommonName` - Certificate common name
- `.Organization` - Organization names
- `.OrganizationalUnit` - Organizational unit names
- `.Groups` - Group names
- `.Roles` - Role names
- `.Country` - Country names
- `.State` - State names
- `.Locality` - Locality names

#### Shortcuts for Common Headers
For common cases, use these simplified flags:

| Option | Description | Example |
|--------|-------------|---------|
| `--inject-groups` | Inject groups into a header | `--inject-groups "app.svc=X-Groups"` |
| `--inject-roles` | Inject roles into a header | `--inject-roles "app.svc=X-Roles"` |
| `--inject-cn` | Inject common name into a header | `--inject-cn "app.svc=X-User"` |
| `--inject-org` | Inject organization into a header | `--inject-org "app.svc=X-Team"` |
| `--inject-ou` | Inject organizational unit into a header | `--inject-ou "app.svc=X-Department"` |

Example combining both approaches:
```bash
itp \
  --inject-groups "app.svc=X-Groups" \
  --inject-roles "app.svc=X-Roles" \
  --inject-header "app.svc=X-Custom:{{.CommonName}}/{{.Organization}}"
```

This will inject three headers for requests to `app.svc`:
1. `X-Groups` containing the comma-separated list of groups
2. `X-Roles` containing the comma-separated list of roles
3. `X-Custom` containing the common name and organization in a custom format

### TLS Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `--cert` | Server certificate file or 'auto' for auto-generated | `auto` |
| `--key` | Server key file or 'auto' for auto-generated | `auto` |
| `--ca` | CA certificate file for server cert (only used with auto-generated certs) | |
| `--listen` | Address to listen on | `:8443` |
| `--verify-client` | Require client certificate | `true` |

## Echo Server

ITP includes a diagnostic echo server that returns detailed TLS connection information:

```bash
itp --echo-server --listen :8443
```

Example output:
```json
{
  "remote_addr": "client.example.com:45678",
  "local_addr": "server.example.com:8443",
  "tls": {
    "version": "TLS_1.3",
    "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "server_name": "echo.example.com",
    "client_cert_provided": true,
    "client_cert_subject": "CN=client.example.com,O=Example Org"
  }
}
```

## Development

### Prerequisites

- Go 1.19 or later
- Make

### Building

```bash
make build      # Build binary
make test       # Run tests
make coverage   # Generate coverage report
```

### Project Structure

```
.
├── cmd/                  # Command-line interface
├── pkg/                  # Core packages
│   ├── certstore/       # Certificate management
│   ├── echo/           # Echo server implementation
│   ├── identity/       # Identity translation
│   ├── proxy/          # TLS proxy implementation
│   ├── router/         # Routing logic
│   └── tls/            # TLS configuration
└── examples/            # Usage examples
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors who have helped shape ITP
- Built with ❤️ using Go's excellent crypto/tls package