# Cloudflare Tunnel Deployment

Recommended first deployment:

```text
play.inc-realm.com
  -> Cloudflare edge
  -> named Cloudflare Tunnel
  -> cloudflared on the game VM
  -> http://127.0.0.1:8789
```

The VM should not expose the gateway port publicly. The gateway should bind to
`127.0.0.1`.

## Gateway Service

Install the gateway binary somewhere root-owned:

```sh
install -o root -g root -m 0755 incarnate-web-gateway /usr/local/bin/incarnate-web-gateway
```

Create the unprivileged service account:

```sh
useradd --system --home /var/lib/incarnate-web-gateway --shell /usr/sbin/nologin incarnate-gateway
```

Install `systemd/incarnate-web-gateway.service`, set environment values, then:

```sh
systemctl daemon-reload
systemctl enable --now incarnate-web-gateway
systemctl status incarnate-web-gateway
```

## Tunnel Route

Cloudflare Tunnel ingress should route the public hostname to the local gateway:

```yaml
ingress:
  - hostname: play.inc-realm.com
    service: http://127.0.0.1:8789
  - service: http_status:404
```

Cloudflare Access can be placed in front temporarily for private beta gating.
Access is not a replacement for Incarnate account passkey auth.

Auth rate limits trust `CF-Connecting-IP` only when the direct peer is in
`INCARNATE_GATEWAY_TRUSTED_PROXY_CIDRS`. The default trusted proxy CIDRs are
loopback only, which matches a local `cloudflared -> 127.0.0.1:8789` deployment.
Do not add broad Cloudflare edge ranges here unless the gateway is directly
exposed to those ranges.

## Production Checks

- `GET https://play.inc-realm.com/healthz` returns `200`
- direct VM public scans do not reach `8789`
- Java AI socket remains private
- the systemd unit allows only loopback network traffic for the gateway process
- auth routes reject wrong origins
- auth rate limits use distinct browser IPs through `CF-Connecting-IP`
- `/play/ws` rejects missing sessions
- logs contain audit events but no secrets
