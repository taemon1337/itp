# ITS - Identity Translation Proxy

The Identity Translation Proxy translated incoming mTLS connections to upstream mTLS connections from a different security domain.

## Architecture | Design

- Accept mTLS connections on a specific port
- Perform a SNI based routing to determine where to proxy the connection
- Proxy the connection to the upstream server
- Dynamically select a TLS certificate to use on upstream connections based on the incoming connection TLS client certificate DN
- Allow routing via DNS, static routing and route pattern


## ITP Routing

Since the ITP is at its core a proxy, it needs to determine where to proxy incoming connections to.

1. Route via DNS based on SNI (default routing, but depends on DNS)
2. Static route provided at start up (by `--route <route>` from cli)
3. Route Pattern (`example.com -> example.cluster.local`)


### Route via DNS

In this mode, which is the default routing mode, the ITP will perform a DNS lookup on the SNI of the incoming connection and route the upstream connection to it.  This assumes the incoming SNI will be resolvable by the ITP which is not always the case in an edge proxy.

Since other routing modes route from one domain to another, the destination route will still be looked up in DNS so this method is the defacto default :)


### Static Routing

A static route is provided at startup and will only be updated when the ITP is restarted, it also has the highest priority of any routing mode.

```bash
--route app.cluster.com=app.default.svc.cluster.local
```


### Route Pattern

A route pattern is a standard way to translate between an incoming SNI and the destination server.

Examples look like this:
```bash

--route-pattern *.*.cluster.com=*.<namespace>.svc.cluster.local
```

### Identity Translation

The main purpose of ITP is to translate incoming mTLS connections to upstream mTLS connections from a different security domain.  Normally this means mapping an externally controller TLS client certificate to an internal identity that can be updated internally on demand for different user group|roles.

The identity translation can be configured based on the following parameters:

- Map Client Certificate Common Name
- Map Client Certificate Organization
- Map Client Certificate Country
- Map Client Certificate State
- Map Client Certificate Locality
- Map Client Certificate Organizational Unit

```bash
--map-common-name <src-cn>=<identity>
--map-organization <src-organization>=<identity>
--map-country <src-country>=<identity>
--map-state <src-state>=<identity>
--map-locality <src-locality>=<identity>
--map-organization-unit <src-organization-unit>=<identity>
```

The internal domain is normally managed by an automated TLS certificate management tool such as Cert-Manager on Kubernetes.  Once a certificate is issued for a particular User (common name) or Group (organization) it can be referenced in the ITP configuration to map to an internal identity.

Additional group|roles can be added to a certificate by using the Common Name or Organization fields and make its way to upstream services to use for authorization decisions.

For example, to map all users in a Organizational Unit to the `cluster-admin` role, the following would be used:

```bash
--map-organization-unit <src-organization-unit>=cluster-admin
```