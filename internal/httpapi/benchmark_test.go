package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mshilts/incarnate-web-gateway/internal/config"
	"github.com/mshilts/incarnate-web-gateway/internal/ratelimit"
)

func BenchmarkBaselineHealthz(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status = %d", rec.Code)
		}
	}
}

func BenchmarkGatewayHealthz(b *testing.B) {
	handler := benchmarkServer(b).Handler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status = %d", rec.Code)
		}
	}
}

func BenchmarkGatewayLoginOptionsPerimeter(b *testing.B) {
	server := benchmarkServer(b)
	server.authLimit = ratelimit.New(1<<30, time.Minute)
	handler := server.Handler()
	body := []byte(`{"account":"latency-probe"}`)

	b.ReportAllocs()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", bytes.NewReader(body))
		req.Header.Set("Origin", config.DefaultPublicOrigin)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			b.Fatalf("status = %d", rec.Code)
		}
	}
}

func benchmarkServer(tb testing.TB) *Server {
	tb.Helper()
	server, err := NewServer(config.Config{
		Bind:              config.DefaultBind,
		PublicOrigin:      config.DefaultPublicOrigin,
		AllowedOrigins:    []string{config.DefaultPublicOrigin},
		RPID:              config.DefaultRPID,
		RPName:            config.DefaultRPName,
		JavaHost:          config.DefaultJavaHost,
		JavaPort:          config.DefaultJavaPort,
		GatewayID:         config.DefaultGatewayID,
		SessionCookieName: config.DefaultSessionCookieName,
		SessionTTL:        time.Hour,
		SessionIdleTTL:    time.Minute,
		MaxBodyBytes:      1024,
		MaxFrameBytes:     1024,
		MaxHeaderBytes:    1024,
		ClientIPHeader:    config.DefaultClientIPHeader,
		TrustedProxyCIDRs: config.DefaultTrustedProxyCIDRs(),
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		tb.Fatalf("NewServer: %v", err)
	}
	return server
}
