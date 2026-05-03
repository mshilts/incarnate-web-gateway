package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mshilts/incarnate-web-gateway/internal/config"
)

func testServer(t *testing.T) *Server {
	t.Helper()
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
	}, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestHTTPServerUsesConfiguredHeaderLimit(t *testing.T) {
	server := testServer(t).HTTPServer()
	if server.MaxHeaderBytes != 1024 {
		t.Fatalf("MaxHeaderBytes = %d", server.MaxHeaderBytes)
	}
}

func TestOriginRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", strings.NewReader(`{"account":"matt"}`))
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestPaddedOriginRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", strings.NewReader(`{"account":"matt"}`))
	req.Header.Set("Origin", " "+config.DefaultPublicOrigin)
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestMultipleOriginsRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", strings.NewReader(`{"account":"matt"}`))
	req.Header.Add("Origin", config.DefaultPublicOrigin)
	req.Header.Add("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAuthRoutesRequireJSONContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", strings.NewReader(`{"account":"matt"}`))
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestTrailingJSONRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", strings.NewReader(`{"account":"matt"} {"account":"mallory"}`))
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestOversizedJSONRejectedWith413(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", strings.NewReader(`{"account":"`+strings.Repeat("a", 2048)+`"}`))
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestWebSocketRejectsUnknownLengthBody(t *testing.T) {
	server := testServer(t)
	sessionRecord, err := server.sessions.Create("matt", "cred", "iphone")
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/play/ws", strings.NewReader("body"))
	req.ContentLength = -1
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.AddCookie(&http.Cookie{Name: config.DefaultSessionCookieName, Value: sessionRecord.ID})
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestClientIPUsesCloudflareHeaderOnlyFromLoopback(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.10")
	if got := clientIP(req); got != "203.0.113.10" {
		t.Fatalf("clientIP from trusted loopback proxy = %q", got)
	}

	req.RemoteAddr = "198.51.100.1:1234"
	if got := clientIP(req); got != "198.51.100.1" {
		t.Fatalf("clientIP trusted spoofed forwarding header = %q", got)
	}
}
