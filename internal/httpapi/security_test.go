package httpapi

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mshilts/incarnate-web-gateway/internal/config"
)

type securityRoute struct {
	name   string
	method string
	path   string
	body   string
}

var securityAuthRoutes = []securityRoute{
	{name: "login-options", method: http.MethodPost, path: "/auth/passkey/login/options", body: `{"account":"matt"}`},
	{name: "login-verify", method: http.MethodPost, path: "/auth/passkey/login/verify", body: `{}`},
	{name: "register-options", method: http.MethodPost, path: "/auth/passkey/register/options", body: `{"pairingToken":"pair","label":"iphone"}`},
	{name: "register-verify", method: http.MethodPost, path: "/auth/passkey/register/verify", body: `{}`},
	{name: "signup-options", method: http.MethodPost, path: "/auth/passkey/signup/options", body: `{"account":"new_player","label":"phone"}`},
	{name: "signup-verify", method: http.MethodPost, path: "/auth/passkey/signup/verify", body: `{}`},
}

func TestSecurityHTTPRejectsOriginConfusionOnProtectedRoutes(t *testing.T) {
	routes := append([]securityRoute{}, securityAuthRoutes...)
	routes = append(routes, securityRoute{name: "play-ws", method: http.MethodGet, path: "/play/ws"})

	for _, route := range routes {
		for _, tc := range []struct {
			name  string
			setup func(*http.Request)
		}{
			{name: "missing", setup: func(*http.Request) {}},
			{name: "wrong", setup: func(req *http.Request) {
				req.Header.Set("Origin", "https://evil.example")
			}},
			{name: "padded", setup: func(req *http.Request) {
				req.Header.Set("Origin", " "+config.DefaultPublicOrigin)
			}},
			{name: "multiple", setup: func(req *http.Request) {
				req.Header.Add("Origin", config.DefaultPublicOrigin)
				req.Header.Add("Origin", "https://evil.example")
			}},
		} {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				req := securityRequest(route)
				tc.setup(req)
				rec := httptest.NewRecorder()
				testServer(t).Handler().ServeHTTP(rec, req)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
				}
			})
		}
	}
}

func TestSecurityHTTPAuthRejectsBadContentTypes(t *testing.T) {
	for _, route := range securityAuthRoutes {
		for _, tc := range []struct {
			name        string
			contentType string
		}{
			{name: "missing", contentType: ""},
			{name: "plain-text", contentType: "text/plain"},
			{name: "form", contentType: "application/x-www-form-urlencoded"},
		} {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				req := securityRequest(route)
				req.Header.Set("Origin", config.DefaultPublicOrigin)
				if tc.contentType != "" {
					req.Header.Set("Content-Type", tc.contentType)
				}
				rec := httptest.NewRecorder()
				testServer(t).Handler().ServeHTTP(rec, req)
				if rec.Code != http.StatusUnsupportedMediaType {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnsupportedMediaType)
				}
			})
		}
	}
}

func TestSecurityHTTPAuthRejectsMalformedJSON(t *testing.T) {
	for _, route := range securityAuthRoutes {
		for _, tc := range []struct {
			name string
			body string
			want int
		}{
			{name: "malformed", body: `{"account":`, want: http.StatusBadRequest},
			{name: "trailing-json", body: route.body + ` {}`, want: http.StatusBadRequest},
			{name: "oversized", body: `{"account":"` + strings.Repeat("a", 2048) + `"}`, want: http.StatusRequestEntityTooLarge},
		} {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				req := securityRequest(securityRoute{method: route.method, path: route.path, body: tc.body})
				req.Header.Set("Origin", config.DefaultPublicOrigin)
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				testServer(t).Handler().ServeHTTP(rec, req)
				if rec.Code != tc.want {
					t.Fatalf("status = %d, want %d", rec.Code, tc.want)
				}
			})
		}
	}
}

func TestSecurityHTTPAuthRejectsSchemaConfusion(t *testing.T) {
	cases := []struct {
		name  string
		route securityRoute
		body  string
		want  int
	}{
		{
			name:  "login-options-unknown-field",
			route: securityRoute{method: http.MethodPost, path: "/auth/passkey/login/options"},
			body:  `{"account":"matt","admin":true}`,
			want:  http.StatusBadRequest,
		},
		{
			name:  "login-options-missing-account",
			route: securityRoute{method: http.MethodPost, path: "/auth/passkey/login/options"},
			body:  `{}`,
			want:  http.StatusBadRequest,
		},
		{
			name:  "register-options-unknown-field",
			route: securityRoute{method: http.MethodPost, path: "/auth/passkey/register/options"},
			body:  `{"pairingToken":"pair","label":"iphone","admin":true}`,
			want:  http.StatusBadRequest,
		},
		{
			name:  "register-options-missing-pairing-token",
			route: securityRoute{method: http.MethodPost, path: "/auth/passkey/register/options"},
			body:  `{"label":"iphone"}`,
			want:  http.StatusBadRequest,
		},
		{
			name:  "register-options-missing-label",
			route: securityRoute{method: http.MethodPost, path: "/auth/passkey/register/options"},
			body:  `{"pairingToken":"pair"}`,
			want:  http.StatusBadRequest,
		},
		{
			name:  "signup-options-unknown-field",
			route: securityRoute{method: http.MethodPost, path: "/auth/passkey/signup/options"},
			body:  `{"account":"new_player","label":"phone","admin":true}`,
			want:  http.StatusBadRequest,
		},
		{
			name:  "signup-options-missing-account",
			route: securityRoute{method: http.MethodPost, path: "/auth/passkey/signup/options"},
			body:  `{"label":"phone"}`,
			want:  http.StatusBadRequest,
		},
		{
			name:  "signup-options-missing-label",
			route: securityRoute{method: http.MethodPost, path: "/auth/passkey/signup/options"},
			body:  `{"account":"new_player"}`,
			want:  http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := securityRequest(securityRoute{method: tc.route.method, path: tc.route.path, body: tc.body})
			req.Header.Set("Origin", config.DefaultPublicOrigin)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			testServer(t).Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestSecurityHTTPAddsBrowserHardeningHeaders(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.WriteFile(staticDir+"/index.html", []byte("<!doctype html><title>Incarnate</title>"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg := testConfig()
	cfg.PlayStaticDir = staticDir
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	for _, route := range []securityRoute{
		{name: "healthz", method: http.MethodGet, path: "/healthz"},
		{name: "play-static", method: http.MethodGet, path: "/play/"},
		{name: "auth-rejection", method: http.MethodPost, path: "/auth/passkey/login/options", body: `{"account":"matt"}`},
		{name: "websocket-rejection", method: http.MethodGet, path: "/play/ws"},
	} {
		t.Run(route.name, func(t *testing.T) {
			req := securityRequest(route)
			if strings.HasPrefix(route.path, "/auth/") || route.path == "/play/ws" {
				req.Header.Set("Origin", config.DefaultPublicOrigin)
			}
			if strings.HasPrefix(route.path, "/auth/") {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			assertBrowserHardeningHeaders(t, rec.Header(), true)
		})
	}
}

func TestSecurityHTTPRedirectsPublicHTTPToHTTPS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://play.inc-realm.com/play/?slot=1", nil)
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPermanentRedirect)
	}
	if got := rec.Header().Get("Location"); got != "https://play.inc-realm.com/play/?slot=1" {
		t.Fatalf("Location = %q", got)
	}
	assertBrowserHardeningHeaders(t, rec.Header(), true)
}

func TestSecurityHTTPSRedirectTrustsXForwardedProtoOnlyFromTrustedProxy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		remoteAddr string
		headerName string
		header     string
		want       int
	}{
		{name: "trusted-x-forwarded-proto", remoteAddr: "127.0.0.1:1000", headerName: "X-Forwarded-Proto", header: "https", want: http.StatusOK},
		{name: "trusted-forwarded", remoteAddr: "127.0.0.1:1000", headerName: "Forwarded", header: "for=203.0.113.10;proto=https;host=play.inc-realm.com", want: http.StatusPermanentRedirect},
		{name: "untrusted-x-forwarded-proto", remoteAddr: "198.51.100.1:1000", headerName: "X-Forwarded-Proto", header: "https", want: http.StatusPermanentRedirect},
		{name: "ambiguous-x-forwarded-proto", remoteAddr: "127.0.0.1:1000", headerName: "X-Forwarded-Proto", header: "https,http", want: http.StatusPermanentRedirect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://play.inc-realm.com/healthz", nil)
			req.RemoteAddr = tc.remoteAddr
			req.Header.Set(tc.headerName, tc.header)
			rec := httptest.NewRecorder()
			testServer(t).Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestSecurityHTTPDevOriginDoesNotRedirectOrSendHSTS(t *testing.T) {
	cfg := testConfig()
	cfg.PublicOrigin = "http://127.0.0.1:5173"
	cfg.AllowedOrigins = []string{cfg.PublicOrigin}
	cfg.CookieSecure = false
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:5173/healthz", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("Strict-Transport-Security = %q", got)
	}
	assertBrowserHardeningHeaders(t, rec.Header(), false)
}

func TestSecurityHTTPWebSocketRejectsUnauthenticatedOrMalformedUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *Server, *http.Request)
		want  int
	}{
		{
			name: "missing-session",
			setup: func(*testing.T, *Server, *http.Request) {
			},
			want: http.StatusUnauthorized,
		},
		{
			name: "empty-session",
			setup: func(_ *testing.T, _ *Server, req *http.Request) {
				req.AddCookie(&http.Cookie{Name: config.DefaultSessionCookieName})
			},
			want: http.StatusUnauthorized,
		},
		{
			name: "unknown-session",
			setup: func(_ *testing.T, _ *Server, req *http.Request) {
				req.AddCookie(&http.Cookie{Name: config.DefaultSessionCookieName, Value: "missing"})
			},
			want: http.StatusUnauthorized,
		},
		{
			name: "expired-session",
			setup: func(t *testing.T, server *Server, req *http.Request) {
				now := time.Unix(1000, 0)
				server.sessions.SetClock(func() time.Time { return now })
				record, err := server.sessions.Create("matt", "cred", "iphone")
				if err != nil {
					t.Fatalf("Create session: %v", err)
				}
				now = now.Add(2 * time.Minute)
				req.AddCookie(&http.Cookie{Name: config.DefaultSessionCookieName, Value: record.ID})
			},
			want: http.StatusUnauthorized,
		},
		{
			name: "known-length-body",
			setup: func(t *testing.T, server *Server, req *http.Request) {
				addValidSession(t, server, req)
				req.Body = http.NoBody
				req.ContentLength = 1
			},
			want: http.StatusBadRequest,
		},
		{
			name: "unknown-length-body",
			setup: func(t *testing.T, server *Server, req *http.Request) {
				addValidSession(t, server, req)
				req.ContentLength = -1
			},
			want: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := testServer(t)
			req := securityRequest(securityRoute{method: http.MethodGet, path: "/play/ws"})
			req.Header.Set("Origin", config.DefaultPublicOrigin)
			tc.setup(t, server, req)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestSecurityHTTPRateLimitUsesTrustedClientIdentity(t *testing.T) {
	t.Run("same-cloudflare-client-is-limited", func(t *testing.T) {
		server := testServer(t)
		for i := 0; i < 20; i++ {
			rec := serveRateLimitedLogin(t, server, "127.0.0.1:1000", "203.0.113.10")
			if rec.Code == http.StatusTooManyRequests {
				t.Fatalf("request %d was limited early", i+1)
			}
		}
		rec := serveRateLimitedLogin(t, server, "127.0.0.1:1000", "203.0.113.10")
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
		}
	})

	t.Run("different-cloudflare-client-is-not-collapsed", func(t *testing.T) {
		server := testServer(t)
		for i := 0; i < 20; i++ {
			_ = serveRateLimitedLogin(t, server, "127.0.0.1:1000", "203.0.113.10")
		}
		rec := serveRateLimitedLogin(t, server, "127.0.0.1:1000", "203.0.113.11")
		if rec.Code == http.StatusTooManyRequests {
			t.Fatal("different trusted CF-Connecting-IP was incorrectly rate limited")
		}
	})

	t.Run("spoofed-cloudflare-header-from-non-loopback-is-ignored", func(t *testing.T) {
		server := testServer(t)
		for i := 0; i < 20; i++ {
			rec := serveRateLimitedLogin(t, server, "198.51.100.25:1000", fmt.Sprintf("203.0.113.%d", i))
			if rec.Code == http.StatusTooManyRequests {
				t.Fatalf("request %d was limited early", i+1)
			}
		}
		rec := serveRateLimitedLogin(t, server, "198.51.100.25:1000", "203.0.113.99")
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
		}
	})
}

func TestSecurityHTTPForwardedClientIPRejectsAmbiguousOrInvalidHeaders(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		headers    []string
		want       string
	}{
		{name: "no-header", remoteAddr: "127.0.0.1:1234", want: "127.0.0.1"},
		{name: "invalid-ip", remoteAddr: "127.0.0.1:1234", headers: []string{"not-an-ip"}, want: "127.0.0.1"},
		{name: "comma-list", remoteAddr: "127.0.0.1:1234", headers: []string{"203.0.113.10, 203.0.113.11"}, want: "127.0.0.1"},
		{name: "multiple-headers", remoteAddr: "127.0.0.1:1234", headers: []string{"203.0.113.10", "203.0.113.11"}, want: "127.0.0.1"},
		{name: "non-loopback-peer", remoteAddr: "198.51.100.1:1234", headers: []string{"203.0.113.10"}, want: "198.51.100.1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := testServer(t)
			req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", nil)
			req.RemoteAddr = tc.remoteAddr
			for _, header := range tc.headers {
				req.Header.Add(config.DefaultClientIPHeader, header)
			}
			if got := server.clientIP(req); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSecurityHTTPServerRejectsOversizedHeaders(t *testing.T) {
	server := testServer(t).HTTPServer()
	server.MaxHeaderBytes = 512
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			done <- err
			return
		}
		done <- nil
	}()
	defer func() {
		_ = server.Close()
		if err := <-done; err != nil {
			t.Fatalf("Serve: %v", err)
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	_, err = fmt.Fprintf(conn, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Fill: %s\r\n\r\n", strings.Repeat("a", 2*1024*1024))
	if err != nil {
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("oversized header request succeeded")
		}
	}
}

func securityRequest(route securityRoute) *http.Request {
	var body *strings.Reader
	if route.body == "" {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(route.body)
	}
	req := httptest.NewRequest(route.method, route.path, body)
	if route.body == "" {
		req.Body = http.NoBody
		req.ContentLength = 0
	}
	return req
}

func addValidSession(t *testing.T, server *Server, req *http.Request) {
	t.Helper()
	record, err := server.sessions.Create("matt", "cred", "iphone")
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: config.DefaultSessionCookieName, Value: record.ID})
}

func serveRateLimitedLogin(t *testing.T, server *Server, remoteAddr, cfConnectingIP string) *httptest.ResponseRecorder {
	t.Helper()
	req := securityRequest(securityRoute{method: http.MethodPost, path: "/auth/passkey/login/options", body: `{"account":"matt"}`})
	req.RemoteAddr = remoteAddr
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	if cfConnectingIP != "" {
		req.Header.Set(config.DefaultClientIPHeader, cfConnectingIP)
	}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	return rec
}

func assertBrowserHardeningHeaders(t *testing.T, header http.Header, wantHSTS bool) {
	t.Helper()
	if got := header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if got := header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q", got)
	}
	if got := header.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
	if got := header.Get("Permissions-Policy"); !strings.Contains(got, "geolocation=()") || !strings.Contains(got, "microphone=()") {
		t.Fatalf("Permissions-Policy = %q", got)
	}
	csp := header.Get("Content-Security-Policy")
	for _, directive := range []string{
		"default-src 'self'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"script-src 'self'",
		"connect-src 'self'",
	} {
		if !strings.Contains(csp, directive) {
			t.Fatalf("Content-Security-Policy = %q, missing %q", csp, directive)
		}
	}
	hsts := header.Get("Strict-Transport-Security")
	if wantHSTS && !strings.Contains(hsts, "max-age=31536000") {
		t.Fatalf("Strict-Transport-Security = %q", hsts)
	}
	if !wantHSTS && hsts != "" {
		t.Fatalf("Strict-Transport-Security = %q", hsts)
	}
}
