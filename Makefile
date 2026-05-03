GO ?= go
PKGS := ./...
BUILD_OUTPUT ?= /tmp/incarnate-web-gateway-check

.PHONY: build test race vet check

build:
	$(GO) build -o $(BUILD_OUTPUT) ./cmd/incarnate-web-gateway

test:
	$(GO) test $(PKGS)

race:
	$(GO) test -race $(PKGS)

vet:
	$(GO) vet $(PKGS)

check: vet test race build
