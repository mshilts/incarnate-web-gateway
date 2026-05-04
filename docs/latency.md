# Latency Measurement

Use two measurements:

- code-path benchmark: isolates gateway handler overhead inside one process
- operational probe: measures real HTTP latency and optional gateway-minus-baseline delta

## Code-Path Benchmark

Run:

```sh
make bench
```

The useful first comparison is:

```text
BenchmarkBaselineHealthz
BenchmarkGatewayHealthz
```

`BaselineHealthz` is a minimal handler that writes the same health response.
`GatewayHealthz` adds the actual gateway mux and body-limit wrapper. The
difference is the local Go handler overhead before network, Cloudflare Tunnel,
or Java backend work.

## Operational Probe

Build the probe:

```sh
make latency-probe
```

Measure a deployed gateway:

```sh
/tmp/incarnate-web-gateway-latency-probe \
  -gateway https://play.inc-realm.com/healthz \
  -requests 1000 \
  -warmup 50 \
  -expect-status 200
```

Compare gateway latency against a baseline URL:

```sh
/tmp/incarnate-web-gateway-latency-probe \
  -baseline http://127.0.0.1:8083/healthz \
  -gateway http://127.0.0.1:8789/healthz \
  -requests 1000 \
  -warmup 50 \
  -expect-status 200
```

For public auth perimeter latency, measure the placeholder login-options route:

```sh
/tmp/incarnate-web-gateway-latency-probe \
  -gateway https://play.inc-realm.com/auth/passkey/login/options \
  -method POST \
  -header 'Origin: https://play.inc-realm.com' \
  -header 'Content-Type: application/json' \
  -body '{"account":"latency-probe"}' \
  -requests 1000 \
  -warmup 50 \
  -expect-status 501
```

Keep `-concurrency 1` for latency overhead. Raising concurrency is a load test
and will include queueing effects.

The current gateway does not yet proxy a real Java gameplay transaction. Once
`/play/ws` is implemented, add a WebSocket transaction probe that measures:

```text
direct Java socket transaction latency
gateway WebSocket transaction latency
gateway minus direct delta
```
