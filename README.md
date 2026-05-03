# incarnate-web-gateway

`incarnate-web-gateway` is the planned browser-native edge gateway for Incarnate.
It is a small Go service that will sit between `https://play.inc-realm.com` and
the private Java AI socket on the game VM.

Status: `v0.1` skeleton. It compiles, has focused security-oriented unit tests,
and exposes the first HTTP route shape. Passkey ceremonies and the WebSocket
Java proxy are intentionally placeholders until the Java gateway-control
commands land.

## Why This Exists

The current desktop and agent path is:

```text
Browser or agent -> local @inc-realm/bridge -> SSH tunnel -> Java AI socket
```

That is the right model for operators, local development, and AI agents because
OpenSSH owns host trust, transport security, and key management. It is the wrong
model for ordinary phone browsers because a phone browser cannot install and run
the local bridge.

The browser-native path is:

```text
Browser -> Cloudflare edge -> Cloudflare Tunnel -> incarnate-web-gateway -> Java AI socket
```

The gateway terminates the public web surface. Java stays private.

## Security Model

The gateway is deliberately narrow:

- strict configured origins only, no wildcard origins
- explicit WebAuthn RP ID and RP name
- short-lived opaque browser sessions stored server-side
- `HttpOnly`, `Secure`, same-site cookies when sessions are issued
- HMAC-signed gateway assertions for Java control commands
- request body and future WebSocket frame limits
- rate limits on public auth routes
- no gameplay logic
- no account-file parsing or writes
- no payment handling
- no admin UI
- no plugin execution
- no database in the first version

Java remains authoritative for account existence, credential activation,
character allowlists, roster state, and every gameplay command.

## Passkeys

Passkeys are the intended browser credential. In the full implementation:

1. A trusted bridge or operator session creates a short-lived pairing token.
2. The browser uses that token to start WebAuthn registration.
3. The gateway verifies the passkey ceremony.
4. The gateway asks Java, over a local HMAC-protected command, to store the
   credential on the Incarnate account.
5. Login creates a short-lived opaque browser session.
6. `/play/ws` opens only after origin and session checks pass.

Open self-service passkey registration is not part of `v0.1`.

## Relationship To `@inc-realm/bridge`

`@inc-realm/bridge` remains the SSH-first path for desktop users, operators,
local development, and AI agents.

This gateway is the phone/browser path. It does not replace the bridge. It
exists because browser-native play needs HTTPS, WebAuthn, cookies, and WSS at a
public origin without making the preserved Java runtime a public web terminator.

## Repository Shape

```text
cmd/incarnate-web-gateway/main.go
internal/config/
internal/httpapi/
internal/passkeys/
internal/session/
internal/javawire/
internal/ratelimit/
internal/audit/
systemd/incarnate-web-gateway.service
docs/configuration.md
docs/security.md
docs/deployment-cloudflare-tunnel.md
```

## Build And Test

```sh
make check
go run ./cmd/incarnate-web-gateway
```

The default bind address is `127.0.0.1:8789`.

## Configuration

The gateway is configured by environment variables:

```text
INCARNATE_GATEWAY_BIND=127.0.0.1:8789
INCARNATE_GATEWAY_PUBLIC_ORIGIN=https://play.inc-realm.com
INCARNATE_GATEWAY_ALLOWED_ORIGINS=https://play.inc-realm.com
INCARNATE_GATEWAY_RP_ID=inc-realm.com
INCARNATE_GATEWAY_RP_NAME=Incarnate
INCARNATE_GATEWAY_JAVA_HOST=127.0.0.1
INCARNATE_GATEWAY_JAVA_PORT=8083
INCARNATE_GATEWAY_ID=prod-play-gateway-1
INCARNATE_GATEWAY_HMAC_SECRET_FILE=/etc/incarnate/web-gateway.hmac
INCARNATE_GATEWAY_SESSION_SECRET_FILE=/etc/incarnate/web-gateway.session
INCARNATE_GATEWAY_LOG_LEVEL=info
INCARNATE_GATEWAY_MAX_HEADER_BYTES=16384
INCARNATE_GATEWAY_CLIENT_IP_HEADER=CF-Connecting-IP
INCARNATE_GATEWAY_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
```

Production must use explicit HTTPS origins. Wildcards are rejected. The service
fails closed on malformed typed configuration and requires loopback bind and
Java backend addresses.

See [docs/configuration.md](docs/configuration.md) for the full list.

## Current Routes

- `GET /healthz`
- `POST /auth/passkey/login/options`
- `POST /auth/passkey/login/verify`
- `POST /auth/passkey/register/options`
- `POST /auth/passkey/register/verify`
- `GET /play/ws`

The passkey and WebSocket routes enforce the first perimeter checks but return
`501 Not Implemented` in `v0.1` where Java protocol support is still pending.

## Release

`v0.1.0` is the first clean skeleton tag when tests pass.
