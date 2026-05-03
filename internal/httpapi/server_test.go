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

func TestOriginRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", strings.NewReader(`{"account":"matt"}`))
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}
