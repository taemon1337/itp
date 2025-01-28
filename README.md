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

## Installation

```bash
go install github.com/taemon1337/itp@latest
```

Or build from source:

```bash
git clone https://github.com/taemon1337/itp.git
cd itp
make build
```

## Quick Start

1. Start the proxy with basic configuration:
```bash
itp --listen :8443 \
    --cert server.crt \
    --key server.key \
    --ca ca.crt
```

2. Add identity mappings:
```bash
itp --listen :8443 \
    --cert server.crt \
    --key server.key \
    --ca ca.crt \
    --map-organization "ExternalOrg=InternalGroup" \
    --map-common-name "external.user@example.com=internal.user"
```

## Configuration

### Routing Options

ITP supports three routing modes in order of priority:

1. **Static Routes** (Highest Priority)
   ```bash
   --route app.cluster.com=app.default.svc.cluster.local
   ```

2. **Route Patterns**
   ```bash
   --route-pattern "*.*.cluster.com=*.<namespace>.svc.cluster.local"
   ```

3. **DNS-based Routing** (Default)
   - Automatically routes based on SNI domain resolution

### Identity Translation

ITP supports two types of identity translation:

1. **Direct Field Mapping**: Map certificate fields directly to new values
2. **Conditional Role/Group Injection**: Add roles and groups based on certificate attributes

#### Direct Field Mapping

Map certificate fields to internal identities using these options:

| Field | Command | Example |
|-------|---------|---------|
| Common Name | `--map-common-name` | `--map-common-name "external.user=internal.user"` |
| Organization | `--map-organization` | `--map-organization "ExternalOrg=InternalTeam"` |
| Org Unit | `--map-organization-unit` | `--map-organization-unit "ExternalOU=InternalOU"` |
| Country | `--map-country` | `--map-country "US=USA"` |
| State | `--map-state` | `--map-state "CA=California"` |
| Locality | `--map-locality` | `--map-locality "SanFrancisco=SF"` |

#### Conditional Role/Group Injection

Add roles and groups to upstream certificates based on incoming certificate attributes:

| Command | Description | Example |
|---------|-------------|---------|
| `--add-role-to-cn` | Add roles when CN matches | `--add-role-to-cn "admin@example.com=cluster-admin,developer"` |
| `--add-role-to-org` | Add roles when Organization matches | `--add-role-to-org "platform-team=operator,deployer"` |
| `--add-role-to-ou` | Add roles when OU matches | `--add-role-to-ou "engineering=developer,debugger"` |
| `--add-group-to-cn` | Add groups when CN matches | `--add-group-to-cn "admin@example.com=platform-admins,sre"` |
| `--add-group-to-org` | Add groups when Organization matches | `--add-group-to-org "platform-team=platform,infra"` |
| `--add-group-to-ou` | Add groups when OU matches | `--add-group-to-ou "engineering=eng-team,builders"` |

Example using both mapping types:
```bash
itp --listen :8443 \
    --cert server.crt \
    --key server.key \
    --ca ca.crt \
    # Direct field mapping
    --map-common-name "external.admin=internal.admin" \
    --map-organization "external-team=internal-team" \
    # Conditional role/group injection
    --add-role-to-cn "external.admin=cluster-admin,developer" \
    --add-group-to-org "external-team=platform-admins,sre"
```

This configuration would:
1. Map CN "external.admin" to "internal.admin"
2. Map Organization "external-team" to "internal-team"
3. Add roles "cluster-admin" and "developer" when CN is "external.admin"
4. Add groups "platform-admins" and "sre" when Organization contains "external-team"

The resulting upstream certificate would have:
- CN: "internal.admin"
- Organization: ["internal-team", "platform-admins", "sre"]
- OrganizationalUnit: ["cluster-admin", "developer"]

### TLS Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `--cert` | Server certificate file | Required |
| `--key` | Server private key file | Required |
| `--ca` | CA certificate for client verification | Required |
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