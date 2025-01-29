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
   
2. **Role and Group Enhancement** (Phase 2)
   - After the basic translation, ITP can add roles and groups based on the *translated* certificate fields
   - This happens through conditional mapping flags (`--add-role-to-*` and `--add-group-to-*`)
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

#### Conditional Role/Group Injection (Phase 2)

Add roles and groups to upstream certificates based on incoming certificate attributes:

| Command | Description | Example |
|---------|-------------|---------|
| `--add-role-to-cn` | Add roles when CN matches | `--add-role-to-cn "admin@example.com=cluster-admin,developer"` |
| `--add-role-to-org` | Add roles when Organization matches | `--add-role-to-org "platform-team=operator,deployer"` |
| `--add-role-to-ou` | Add roles when OU matches | `--add-role-to-ou "engineering=developer,debugger"` |
| `--add-group-to-cn` | Add groups when CN matches | `--add-group-to-cn "admin@example.com=platform-admins,sre"` |
| `--add-group-to-org` | Add groups when Organization matches | `--add-group-to-org "platform-team=platform,infra"` |
| `--add-group-to-ou` | Add groups when OU matches | `--add-group-to-ou "engineering=eng-team,builders"` |

#### Example Flow

Here's a complete example of how identity translation works:

```bash
itp --listen :8443 \
    --map-common-name "external-user=internal-user" \
    --add-role-to-cn "internal-user=admin,reader" \
    --add-group-to-org "external-org=group1,group2"
```

When a client connects with a certificate:
1. CN="external-user", O="external-org"
2. Phase 1 (Basic Translation):
   - CN is mapped to "internal-user" (due to --map-common-name)
   - O remains "external-org" (no explicit mapping)
3. Phase 2 (Role/Group Enhancement):
   - Roles ["admin", "reader"] are added (CN matches "internal-user")
   - Groups ["group1", "group2"] are added (O matches "external-org")
4. Final Identity:
   - CN: "internal-user"
   - O: "external-org"
   - Roles: ["admin", "reader"]
   - Groups: ["group1", "group2"]

### Inject HTTP headers

The upstream TLS client certificate will contain the internal user's groups and roles; however, many times the upstream service expects the user's groups and roles in HTTP headers.

To inject these headers, ITP supports both flexible templating and shortcuts for common cases:

#### Flexible Header Injection
Use `--inject-header` for full template control:

| Option | Description | Example |
|--------|-------------|---------|
| `--inject-header` | Inject custom headers using templates | `--inject-header "app.svc=X-Groups:{{.Groups}},app.svc=X-Custom:static-value"` |

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