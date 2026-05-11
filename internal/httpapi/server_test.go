package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mshilts/incarnate-web-gateway/internal/config"
	"github.com/mshilts/incarnate-web-gateway/internal/javawire"
	"github.com/mshilts/incarnate-web-gateway/internal/passkeys"
	"nhooyr.io/websocket"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	server, err := NewServer(testConfig(), nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

func testConfig() config.Config {
	return config.Config{
		Bind:              config.DefaultBind,
		PublicOrigin:      config.DefaultPublicOrigin,
		AllowedOrigins:    []string{config.DefaultPublicOrigin},
		RPID:              config.DefaultRPID,
		RPName:            config.DefaultRPName,
		JavaHost:          config.DefaultJavaHost,
		JavaPort:          config.DefaultJavaPort,
		GatewayID:         config.DefaultGatewayID,
		HMACSecret:        "0123456789abcdef0123456789abcdef",
		SessionCookieName: config.DefaultSessionCookieName,
		CookieSecure:      true,
		SessionTTL:        time.Hour,
		SessionIdleTTL:    time.Minute,
		JavaTimeout:       10 * time.Millisecond,
		MaxBodyBytes:      1024,
		MaxFrameBytes:     1024,
		MaxHeaderBytes:    1024,
		ClientIPHeader:    config.DefaultClientIPHeader,
		TrustedProxyCIDRs: config.DefaultTrustedProxyCIDRs(),
	}
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

func TestPlayStaticServesConfiguredDirectory(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "/play/", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Incarnate") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestPlayStaticServesPackagedGameAssets(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.MkdirAll(staticDir+"/game-assets", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(staticDir+"/game-assets/tile-manifest.json", []byte(`{"black":{"tileName":"black"}}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg := testConfig()
	cfg.PlayStaticDir = staticDir
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/play/game-assets/tile-manifest.json", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"black"`) {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestPlayStaticRedirectsBarePlayPath(t *testing.T) {
	cfg := testConfig()
	cfg.PlayStaticDir = t.TempDir()
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/play", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/play/" {
		t.Fatalf("Location = %q", got)
	}
}

func TestPlayStaticDirMustExist(t *testing.T) {
	cfg := testConfig()
	cfg.PlayStaticDir = t.TempDir() + "/missing"
	if _, err := NewServer(cfg, nil); err == nil {
		t.Fatal("NewServer accepted missing PlayStaticDir")
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

func TestAuthPreflightAllowsConfiguredOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/auth/passkey/login/options", nil)
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != config.DefaultPublicOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q", got)
	}
}

func TestAuthRouteAddsCORSHeadersForConfiguredOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", strings.NewReader(`{"account":"matt"}`))
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != config.DefaultPublicOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
}

func TestLoginOptionsAcceptsDiscoverableRequestWithoutAccount(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", strings.NewReader(`{}`))
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response json: %v", err)
	}
	if body["loginId"] == "" || body["publicKey"] == nil {
		t.Fatalf("body = %+v", body)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != config.DefaultPublicOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
}

func TestAuthPreflightRejectsUnknownOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/auth/passkey/login/options", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
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

func TestUnknownJSONFieldRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", strings.NewReader(`{"account":"matt","admin":true}`))
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

func TestClientIPTrustsConfiguredProxyHeader(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", nil)
	req.RemoteAddr = "127.0.0.1:49152"
	req.Header.Set(config.DefaultClientIPHeader, "203.0.113.7")

	if got := server.clientIP(req); got != "203.0.113.7" {
		t.Fatalf("clientIP = %q", got)
	}
}

func TestClientIPIgnoresSpoofedHeaderFromUntrustedPeer(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", nil)
	req.RemoteAddr = "198.51.100.10:49152"
	req.Header.Set(config.DefaultClientIPHeader, "203.0.113.7")

	if got := server.clientIP(req); got != "198.51.100.10" {
		t.Fatalf("clientIP = %q", got)
	}
}

func TestClientIPRejectsCommaSeparatedHeader(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", nil)
	req.RemoteAddr = "127.0.0.1:49152"
	req.Header.Set(config.DefaultClientIPHeader, "203.0.113.7, 198.51.100.10")

	if got := server.clientIP(req); got != "127.0.0.1" {
		t.Fatalf("clientIP = %q", got)
	}
}

func TestClientIPRejectsDuplicateHeaderLines(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/options", nil)
	req.RemoteAddr = "127.0.0.1:49152"
	req.Header.Add(config.DefaultClientIPHeader, "203.0.113.7")
	req.Header.Add(config.DefaultClientIPHeader, "198.51.100.10")

	if got := server.clientIP(req); got != "127.0.0.1" {
		t.Fatalf("clientIP = %q", got)
	}
}

func TestLoginVerifyIssuesConfiguredSessionCookie(t *testing.T) {
	server := testServer(t)
	server.cfg.CookieSecure = false
	server.passkeys = fakePasskeyService{
		loginVerify: passkeys.AuthenticatedCredential{Account: "matt", CredentialID: "cred", CredentialLabel: "iphone"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/verify", strings.NewReader(`{"loginId":"login-1","response":{"id":"cred"}}`))
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookie count = %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != config.DefaultSessionCookieName || cookie.Value == "" || !cookie.HttpOnly || cookie.Secure {
		t.Fatalf("unexpected cookie: %+v", cookie)
	}
}

func TestSignupVerifyIssuesSessionCookie(t *testing.T) {
	server := testServer(t)
	server.cfg.CookieSecure = false
	server.passkeys = fakePasskeyService{
		signupVerify: passkeys.AuthenticatedCredential{Account: "new_player", CredentialID: "cred", CredentialLabel: "phone"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/signup/verify", strings.NewReader(`{"registrationId":"reg-1","response":{"id":"cred"}}`))
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != config.DefaultSessionCookieName || cookies[0].Value == "" {
		t.Fatalf("unexpected cookies: %+v", cookies)
	}
	if !strings.Contains(rec.Body.String(), `"account":"new_player"`) || !strings.Contains(rec.Body.String(), `"wsUrl":"/play/ws"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestSignupOptionsReturnsConflictForExistingAccount(t *testing.T) {
	server := testServer(t)
	server.passkeys = fakePasskeyService{signupOptionsErr: passkeys.ErrAccountTaken}
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/signup/options", strings.NewReader(`{"account":"matt","label":"passkey"}`))
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("unexpected redirect location: %q", rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Body.String(), `"error":"Account already taken."`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestSignupVerifyReturnsConflictForJavaDuplicateRace(t *testing.T) {
	server := testServer(t)
	server.passkeys = fakePasskeyService{signupVerifyErr: javawire.RejectedError{Message: passkeys.AccountTakenMessage}}
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/signup/verify", strings.NewReader(`{"registrationId":"reg-1","response":{"id":"cred"}}`))
	req.Header.Set("Origin", config.DefaultPublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"Account already taken."`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestPlayWSProxiesAfterJavaSessionBegin(t *testing.T) {
	server := testServer(t)
	server.cfg.MaxFrameBytes = 1024
	record, err := server.sessions.Create("matt", "Y3JlZA", "iphone")
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sessionBegin := make(chan map[string]any, 1)
	server.java.Dialer = func(context.Context, string) (net.Conn, error) {
		javaSide, gatewaySide := net.Pipe()
		go func() {
			reader := bufio.NewReader(javaSide)
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var req map[string]any
			_ = json.Unmarshal(line, &req)
			sessionBegin <- req
			_, _ = javaSide.Write([]byte(`{"type":"gateway_session_result","ok":true,"account":"matt","credentialLabel":"iphone"}` + "\n"))
			line, err = reader.ReadBytes('\n')
			if err != nil {
				return
			}
			_, _ = javaSide.Write(line)
		}()
		return gatewaySide, nil
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/play/ws"
	wsConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Origin": []string{config.DefaultPublicOrigin},
			"Cookie": []string{(&http.Cookie{Name: config.DefaultSessionCookieName, Value: record.ID}).String()},
		},
	})
	if err != nil {
		t.Fatalf("Dial websocket: %v", err)
	}
	defer wsConn.Close(websocket.StatusNormalClosure, "")
	req := <-sessionBegin
	if req["type"] != "gateway_session_begin" || req["account"] != "matt" || req["signature"] == "" {
		t.Fatalf("bad session begin: %+v", req)
	}
	if err := wsConn.Write(ctx, websocket.MessageText, []byte(`{"type":"ping"}`)); err != nil {
		t.Fatalf("websocket write: %v", err)
	}
	messageType, data, err := wsConn.Read(ctx)
	if err != nil {
		t.Fatalf("websocket read: %v", err)
	}
	if messageType != websocket.MessageText || string(data) != `{"type":"ping"}` {
		t.Fatalf("unexpected websocket echo: type=%v data=%s", messageType, data)
	}
}

type fakePasskeyService struct {
	loginVerify      passkeys.AuthenticatedCredential
	signupVerify     passkeys.AuthenticatedCredential
	signupOptionsErr error
	signupVerifyErr  error
}

func (f fakePasskeyService) LoginOptions(context.Context, passkeys.LoginOptionsRequest) (map[string]any, error) {
	return map[string]any{"ok": true}, nil
}

func (f fakePasskeyService) LoginVerify(context.Context, passkeys.LoginVerifyRequest) (passkeys.AuthenticatedCredential, error) {
	return f.loginVerify, nil
}

func (f fakePasskeyService) RegistrationOptions(context.Context, passkeys.RegistrationOptionsRequest) (map[string]any, error) {
	return map[string]any{"ok": true}, nil
}

func (f fakePasskeyService) RegistrationVerify(context.Context, passkeys.RegistrationVerifyRequest) (passkeys.AuthenticatedCredential, error) {
	return passkeys.AuthenticatedCredential{}, nil
}

func (f fakePasskeyService) SignupOptions(context.Context, passkeys.SignupOptionsRequest) (map[string]any, error) {
	if f.signupOptionsErr != nil {
		return nil, f.signupOptionsErr
	}
	return map[string]any{"ok": true}, nil
}

func (f fakePasskeyService) SignupVerify(context.Context, passkeys.SignupVerifyRequest) (passkeys.AuthenticatedCredential, error) {
	if f.signupVerifyErr != nil {
		return passkeys.AuthenticatedCredential{}, f.signupVerifyErr
	}
	return f.signupVerify, nil
}
