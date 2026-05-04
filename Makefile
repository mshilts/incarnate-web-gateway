GO ?= go
PKGS := ./...
BUILD_OUTPUT ?= /tmp/incarnate-web-gateway-check
LATENCY_PROBE_OUTPUT ?= /tmp/incarnate-web-gateway-latency-probe

.PHONY: build gateway latency-probe test race vet bench check

build: gateway latency-probe

gateway:
	$(GO) build -o $(BUILD_OUTPUT) ./cmd/incarnate-web-gateway

latency-probe:
	$(GO) build -o $(LATENCY_PROBE_OUTPUT) ./cmd/latency-probe

test:
	$(GO) test $(PKGS)

race:
	$(GO) test -race $(PKGS)

vet:
	$(GO) vet $(PKGS)

bench:
	$(GO) test -run '^$$' -bench=. -benchmem $(PKGS)

check: vet test race build
