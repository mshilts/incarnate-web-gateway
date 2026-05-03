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
| `INCARNATE_GATEWAY_HMAC_SECRET_FILE` | empty | File containing the gateway-to-Java HMAC secret. |
| `INCARNATE_GATEWAY_SESSION_SECRET_FILE` | empty | Reserved for encrypted/signed session material. |
| `INCARNATE_GATEWAY_LOG_LEVEL` | `info` | Logging level hook. |
| `INCARNATE_GATEWAY_SESSION_COOKIE_NAME` | `incarnate_gateway_session` | Browser session cookie name. |
| `INCARNATE_GATEWAY_SESSION_TTL` | `12h` | Absolute browser session lifetime. |
| `INCARNATE_GATEWAY_SESSION_IDLE_TTL` | `30m` | Idle browser session lifetime. |
| `INCARNATE_GATEWAY_MAX_BODY_BYTES` | `65536` | Maximum HTTP request body size. |
| `INCARNATE_GATEWAY_MAX_FRAME_BYTES` | `65536` | Future maximum WebSocket frame/message size. |

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
The `v0.1` skeleton validates signing primitives but does not load or rotate the
secret file yet.

