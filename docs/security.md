# Security

This repository is a security boundary. The gateway should stay small enough to
audit.

## Trust Boundaries

```text
Browser
  -> Cloudflare edge
  -> Cloudflare Tunnel
  -> incarnate-web-gateway on 127.0.0.1
  -> Java AI socket on 127.0.0.1
```

Cloudflare controls public exposure and TLS at the edge. It is not the game
identity provider.

The gateway owns browser-facing authentication and perimeter checks. Java owns
account state and gameplay authorization.

## Gateway Responsibilities

- check exact `Origin`
- enforce public request body limits
- enforce future WebSocket frame limits
- issue and validate short-lived opaque browser sessions
- rate limit public auth routes
- generate WebAuthn challenges
- verify WebAuthn responses against the configured RP ID and origin
- sign Java gateway-control commands with HMAC
- log audit events without leaking secrets to clients
- fail closed on malformed security-relevant configuration
- trust Cloudflare client IP headers only from the local tunnel process

## Non-Responsibilities

- gameplay logic
- account-file parsing
- account-file writes
- character authorization rules
- payment handling
- operator UI
- generic OAuth/OIDC provider behavior
- direct Cloudflare API access

## Attack Surface To Keep Small

- public auth endpoints
- `/play/ws` upgrade
- Java backend socket lifecycle
- HMAC command signing
- session cookie handling
- origin and RP ID configuration

Every new feature should be tested against those surfaces before it lands.

## Negative Tests Required Before Production

- wildcard origin rejected
- wrong origin rejected for every auth route and `/play/ws`
- expired session rejected
- idle session rejected
- missing HMAC signature rejected by Java
- tampered HMAC payload rejected by Java
- stale Java command rejected by Java
- replayed Java nonce rejected by Java
- expired WebAuthn challenge rejected
- replayed WebAuthn challenge rejected
- oversized HTTP body rejected
- oversized HTTP headers rejected by the Go server
- oversized WebSocket frame rejected
- unauthenticated `/play/ws` rejected

The `v0.1` skeleton includes tests for config parsing, origin allowlisting,
strict JSON request parsing, session lifecycle, HMAC signing, and basic rate
limiting. Security regression coverage lives in package-local
`security_test.go` files so it runs as part of `go test ./...` instead of a
separate script.
