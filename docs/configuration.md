# Configuration

`incarnate-web-gateway` is configured through environment variables so it can be
run directly, under systemd, or behind Cloudflare Tunnel without a separate
config parser.

| Variable | Default | Purpose |
| --- | --- | --- |
| `INCARNATE_GATEWAY_BIND` | `127.0.0.1:8789` | Local HTTP/WSS bind address. |
| `INCARNATE_GATEWAY_PUBLIC_ORIGIN` | `https://play.inc-realm.com` | Canonical browser origin. |
| `INCARNATE_GATEWAY_ALLOWED_ORIGINS` | `https://play.inc-realm.com` | Comma-separated exact origin allowlist. |
| `INCARNATE_GATEWAY_RP_ID` | `inc-realm.com` | WebAuthn relying-party ID. |
| `INCARNATE_GATEWAY_RP_NAME` | `Incarnate` | WebAuthn relying-party display name. |
| `INCARNATE_GATEWAY_JAVA_HOST` | `127.0.0.1` | Private Java AI socket host. |
| `INCARNATE_GATEWAY_JAVA_PORT` | `8083` | Private Java AI socket port. |
| `INCARNATE_GATEWAY_ID` | `dev-play-gateway-1` | Gateway identity included in Java HMAC commands. |
| `INCARNATE_GATEWAY_HMAC_SECRET` | empty | Inline gateway-to-Java HMAC secret for local development. |
| `INCARNATE_GATEWAY_HMAC_SECRET_FILE` | empty | File containing the gateway-to-Java HMAC secret. |
| `INCARNATE_GATEWAY_SESSION_SECRET_FILE` | empty | Reserved for encrypted/signed session material. |
| `INCARNATE_GATEWAY_LOG_LEVEL` | `info` | Logging level hook. |
| `INCARNATE_GATEWAY_SESSION_COOKIE_NAME` | `incarnate_gateway_session` | Browser session cookie name. |
| `INCARNATE_GATEWAY_COOKIE_SECURE` | `true` for HTTPS origins, `false` for HTTP origins | Whether browser session cookies use the `Secure` flag. Set explicitly for localhost/prod. |
| `INCARNATE_GATEWAY_SESSION_TTL` | `12h` | Absolute browser session lifetime. |
| `INCARNATE_GATEWAY_SESSION_IDLE_TTL` | `30m` | Idle browser session lifetime. |
| `INCARNATE_GATEWAY_JAVA_TIMEOUT` | `10s` | Dial/read/write timeout for signed Java gateway-control exchanges. |
| `INCARNATE_GATEWAY_MAX_BODY_BYTES` | `65536` | Maximum HTTP request body size. |
| `INCARNATE_GATEWAY_MAX_FRAME_BYTES` | `65536` | Maximum browser WebSocket and Java NDJSON frame/message size. |
| `INCARNATE_GATEWAY_MAX_HEADER_BYTES` | `16384` | Maximum HTTP request header size. |
| `INCARNATE_GATEWAY_CLIENT_IP_HEADER` | `CF-Connecting-IP` | Single-IP header trusted only from configured proxy CIDRs. |
| `INCARNATE_GATEWAY_TRUSTED_PROXY_CIDRS` | `127.0.0.1/32,::1/128` | Comma-separated proxy CIDRs allowed to supply the client-IP header. Empty disables proxy header trust. |

## Origin Rules

Production origins must be exact HTTPS origins:

```text
https://play.inc-realm.com
```

Wildcard origins are rejected. Plain HTTP is accepted only for localhost
development origins such as:

```text
http://127.0.0.1:5173
http://localhost:5173
```

Do not include localhost origins in production systemd units.

Typed configuration values fail closed. Invalid integers and durations stop the
service instead of silently falling back to defaults.

The gateway bind address and Java socket host must be loopback addresses. The
intended deployment path is local-only gateway exposure through Cloudflare
Tunnel, not a public listener on the VM.

## Client IP Rules

Auth route rate limits use the direct peer IP unless the peer is inside
`INCARNATE_GATEWAY_TRUSTED_PROXY_CIDRS`. For the Cloudflare Tunnel deployment,
the trusted peer is the local `cloudflared` process, so the default loopback
CIDRs trust the `CF-Connecting-IP` header from that process.

The configured client-IP header must contain one IP literal. Comma-separated
forwarded chains are rejected and fall back to the direct peer IP.

Set `INCARNATE_GATEWAY_TRUSTED_PROXY_CIDRS` to an empty value for a direct
deployment with no trusted reverse proxy.

## Secrets

The HMAC secret protects gateway-control commands sent to Java. Use at least 32
random bytes. The file should be readable by the gateway service user and not by
world users.

Example:

```sh
install -d -m 0750 -o root -g incarnate /etc/incarnate
openssl rand -base64 32 > /etc/incarnate/web-gateway.hmac
chown root:incarnate /etc/incarnate/web-gateway.hmac
chmod 0640 /etc/incarnate/web-gateway.hmac
```

Secret rotation should support a current and previous secret before production.
Java already supports current and previous secrets. The gateway currently loads
one current secret from `INCARNATE_GATEWAY_HMAC_SECRET` or
`INCARNATE_GATEWAY_HMAC_SECRET_FILE`; add previous-secret gateway support before
rotating production traffic without a restart window.

## Local Incarnate Test Environment

For a local browser-native path against the Incarnate Java AI socket, run Java
with the same gateway ID and HMAC secret that the Go gateway uses. The gateway
registration route currently needs a local account token because Java does not
yet expose `gateway_pairing_claim`:

```text
INCARNATE_GATEWAY_PUBLIC_ORIGIN=http://localhost:8789
INCARNATE_GATEWAY_ALLOWED_ORIGINS=http://localhost:4174
INCARNATE_GATEWAY_RP_ID=localhost
INCARNATE_GATEWAY_COOKIE_SECURE=false
INCARNATE_GATEWAY_JAVA_HOST=127.0.0.1
INCARNATE_GATEWAY_JAVA_PORT=8083
INCARNATE_GATEWAY_ID=dev-play-gateway-1
INCARNATE_GATEWAY_HMAC_SECRET=<same-32-byte-or-longer-secret-as-java>
```

Use `pairingToken=account:<accountName>` only for local end-to-end testing.
Opaque pairing tokens should remain rejected until Java owns pairing-token
creation and claim.
