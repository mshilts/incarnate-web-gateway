package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/mshilts/incarnate-web-gateway/internal/audit"
	"github.com/mshilts/incarnate-web-gateway/internal/config"
	"github.com/mshilts/incarnate-web-gateway/internal/javawire"
	"github.com/mshilts/incarnate-web-gateway/internal/passkeys"
	"github.com/mshilts/incarnate-web-gateway/internal/ratelimit"
	"github.com/mshilts/incarnate-web-gateway/internal/session"
	"nhooyr.io/websocket"
)

type Server struct {
	cfg       config.Config
	origins   config.OriginAllowlist
	passkeys  passkeys.Service
	java      javawire.Client
	sessions  *session.Store
	authLimit *ratelimit.Limiter
	audit     audit.Logger
	proxies   []netip.Prefix
}

func NewServer(cfg config.Config, logger *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	origins, err := config.NewOriginAllowlist(cfg.AllowedOrigins)
	if err != nil {
		return nil, err
	}
	proxies, err := parseProxyCIDRs(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	secret, err := loadHMACSecret(cfg)
	if err != nil {
		return nil, err
	}
	javaClient := javawire.Client{
		Addr:    cfg.JavaAddress(),
		Timeout: cfg.JavaTimeout,
		MaxLine: int(cfg.MaxFrameBytes),
		Signer: javawire.Signer{
			GatewayID: cfg.GatewayID,
			Secret:    secret,
		},
	}
	passkeyService, err := passkeys.NewWebAuthnService(passkeys.ServiceConfig{
		RPID:                     cfg.RPID,
		RPName:                   cfg.RPName,
		AllowedOrigins:           cfg.AllowedOrigins,
		TTL:                      5 * time.Minute,
		AllowLocalAccountPairing: cfg.AllowLocalAccountPairing,
	}, javaClient)
	if err != nil {
		return nil, err
	}
	if cfg.PlayStaticDir != "" {
		info, err := os.Stat(cfg.PlayStaticDir)
		if err != nil {
			return nil, fmt.Errorf("stat play static dir: %w", err)
		}
		if !info.IsDir() {
			return nil, errors.New("play static dir must be a directory")
		}
	}
	return &Server{
		cfg:       cfg,
		origins:   origins,
		passkeys:  passkeyService,
		java:      javaClient,
		sessions:  session.NewStore(cfg.SessionTTL, cfg.SessionIdleTTL),
		authLimit: ratelimit.New(20, time.Minute),
		audit:     audit.New(logger),
		proxies:   proxies,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("OPTIONS /auth/passkey/login/options", s.authPreflight)
	mux.HandleFunc("POST /auth/passkey/login/options", s.loginOptions)
	mux.HandleFunc("OPTIONS /auth/passkey/login/verify", s.authPreflight)
	mux.HandleFunc("POST /auth/passkey/login/verify", s.loginVerify)
	mux.HandleFunc("OPTIONS /auth/passkey/register/options", s.authPreflight)
	mux.HandleFunc("POST /auth/passkey/register/options", s.registerOptions)
	mux.HandleFunc("OPTIONS /auth/passkey/register/verify", s.authPreflight)
	mux.HandleFunc("POST /auth/passkey/register/verify", s.registerVerify)
	mux.HandleFunc("OPTIONS /auth/passkey/signup/options", s.authPreflight)
	mux.HandleFunc("POST /auth/passkey/signup/options", s.signupOptions)
	mux.HandleFunc("OPTIONS /auth/passkey/signup/verify", s.authPreflight)
	mux.HandleFunc("POST /auth/passkey/signup/verify", s.signupVerify)
	mux.HandleFunc("GET /play/ws", s.playWS)
	if s.cfg.PlayStaticDir != "" {
		mux.HandleFunc("GET /play", s.playStaticRedirect)
		mux.Handle("GET /play/", http.StripPrefix("/play/", http.FileServer(http.Dir(s.cfg.PlayStaticDir))))
	}
	return http.MaxBytesHandler(mux, s.cfg.MaxBodyBytes)
}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.cfg.Bind,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes,
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Server) authPreflight(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrigin(w, r) {
		return
	}
	requestMethod := r.Header.Get("Access-Control-Request-Method")
	if requestMethod != "" && !strings.EqualFold(requestMethod, http.MethodPost) {
		writeError(w, http.StatusForbidden, "cors method is not allowed")
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "content-type")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) loginOptions(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrigin(w, r) || !s.requireRateLimit(w, r, "login-options") {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var req passkeys.LoginOptionsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Account == "" {
		writeError(w, http.StatusBadRequest, "account is required")
		return
	}
	response, err := s.passkeys.LoginOptions(r.Context(), req)
	if errors.Is(err, passkeys.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "passkey login options are not implemented in v0.1")
		return
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "login options rejected")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) loginVerify(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrigin(w, r) || !s.requireRateLimit(w, r, "login-verify") {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var req passkeys.LoginVerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	auth, err := s.passkeys.LoginVerify(r.Context(), req)
	if errors.Is(err, passkeys.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "passkey login verify is not implemented in v0.1")
		return
	}
	if err != nil {
		s.audit.Event(r.Context(), "passkey_login_verify_rejected", "error", err.Error())
		writeError(w, http.StatusUnauthorized, "login verify rejected")
		return
	}
	record, err := s.sessions.Create(auth.Account, auth.CredentialID, auth.CredentialLabel)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session creation failed")
		return
	}
	s.setSessionCookie(w, record)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": auth.Account, "wsUrl": "/play/ws"})
}

func (s *Server) registerOptions(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrigin(w, r) || !s.requireRateLimit(w, r, "register-options") {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var req passkeys.RegistrationOptionsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.PairingToken == "" || req.Label == "" {
		writeError(w, http.StatusBadRequest, "pairingToken and label are required")
		return
	}
	response, err := s.passkeys.RegistrationOptions(r.Context(), req)
	if errors.Is(err, passkeys.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "passkey registration options are not implemented in v0.1")
		return
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "registration options rejected")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) registerVerify(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrigin(w, r) || !s.requireRateLimit(w, r, "register-verify") {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var req passkeys.RegistrationVerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	auth, err := s.passkeys.RegistrationVerify(r.Context(), req)
	if errors.Is(err, passkeys.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "passkey registration verify is not implemented in v0.1")
		return
	}
	if err != nil {
		s.audit.Event(r.Context(), "passkey_registration_verify_rejected", "error", err.Error())
		writeError(w, http.StatusUnauthorized, "registration verify rejected")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": auth.Account})
}

func (s *Server) signupOptions(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrigin(w, r) || !s.requireRateLimit(w, r, "signup-options") {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var req passkeys.SignupOptionsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Account == "" || req.Label == "" {
		writeError(w, http.StatusBadRequest, "account and label are required")
		return
	}
	response, err := s.passkeys.SignupOptions(r.Context(), req)
	if errors.Is(err, passkeys.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "passkey signup options are not implemented")
		return
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "signup options rejected")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) signupVerify(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrigin(w, r) || !s.requireRateLimit(w, r, "signup-verify") {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var req passkeys.SignupVerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	auth, err := s.passkeys.SignupVerify(r.Context(), req)
	if errors.Is(err, passkeys.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "passkey signup verify is not implemented")
		return
	}
	if err != nil {
		s.audit.Event(r.Context(), "passkey_signup_verify_rejected", "error", err.Error())
		writeError(w, http.StatusUnauthorized, "signup verify rejected")
		return
	}
	record, err := s.sessions.Create(auth.Account, auth.CredentialID, auth.CredentialLabel)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session creation failed")
		return
	}
	s.setSessionCookie(w, record)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": auth.Account, "wsUrl": "/play/ws"})
}

func (s *Server) playWS(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrigin(w, r) {
		return
	}
	cookie, err := r.Cookie(s.cfg.SessionCookieName)
	if err != nil || cookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "valid session is required")
		return
	}
	record, err := s.sessions.Get(cookie.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "valid session is required")
		return
	}
	if r.ContentLength != 0 {
		writeError(w, http.StatusBadRequest, "websocket upgrade must not include a request body")
		return
	}
	javaConn, javaReader, _, err := s.java.BeginSession(r.Context(), record.Account, record.CredentialID, record.CredentialLbl, record.ID, record.ExpiresAt)
	if err != nil {
		writeError(w, http.StatusBadGateway, "java session rejected")
		return
	}
	defer javaConn.Close()
	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer wsConn.Close(websocket.StatusInternalError, "proxy closed")
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	errc := make(chan error, 2)
	go func() {
		errc <- proxyBrowserToJava(ctx, wsConn, javaConn, s.cfg.MaxFrameBytes)
		cancel()
	}()
	go func() {
		errc <- proxyJavaToBrowser(ctx, wsConn, javaReader, s.cfg.MaxFrameBytes)
		cancel()
	}()
	err = <-errc
	if err == nil || errors.Is(err, context.Canceled) || websocket.CloseStatus(err) == websocket.StatusNormalClosure {
		_ = wsConn.Close(websocket.StatusNormalClosure, "")
		return
	}
	s.audit.Event(r.Context(), "play_ws_proxy_closed", "error", err.Error())
	_ = wsConn.Close(websocket.StatusPolicyViolation, "proxy violation")
}

func (s *Server) playStaticRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/play/", http.StatusMovedPermanently)
}

func (s *Server) requireOrigin(w http.ResponseWriter, r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) != 1 {
		s.audit.Event(r.Context(), "origin_rejected", "originCount", len(origins), "path", r.URL.Path)
		writeError(w, http.StatusForbidden, "origin is not allowed")
		return false
	}
	origin := origins[0]
	if origin != strings.TrimSpace(origin) {
		s.audit.Event(r.Context(), "origin_rejected", "origin", origin, "path", r.URL.Path)
		writeError(w, http.StatusForbidden, "origin is not allowed")
		return false
	}
	if origin == "" || !s.origins.Allows(origin) {
		s.audit.Event(r.Context(), "origin_rejected", "origin", origin, "path", r.URL.Path)
		writeError(w, http.StatusForbidden, "origin is not allowed")
		return false
	}
	setCORSHeaders(w, origin)
	return true
}

func setCORSHeaders(w http.ResponseWriter, origin string) {
	w.Header().Add("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func (s *Server) requireRateLimit(w http.ResponseWriter, r *http.Request, action string) bool {
	key := action + ":" + s.clientIP(r)
	if !s.authLimit.Allow(key) {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return false
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeJSONDecodeError(w, err)
		return false
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		writeJSONDecodeError(w, err)
		return false
	}
	return true
}

func writeJSONDecodeError(w http.ResponseWriter, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid json")
}

func requireJSONContentType(w http.ResponseWriter, r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": message})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, record session.Record) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.SessionCookieName,
		Value:    record.ID,
		Path:     "/",
		Expires:  record.ExpiresAt,
		MaxAge:   int(time.Until(record.ExpiresAt).Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func loadHMACSecret(cfg config.Config) ([]byte, error) {
	secret := strings.TrimSpace(cfg.HMACSecret)
	if secret == "" && strings.TrimSpace(cfg.HMACSecretFile) != "" {
		raw, err := os.ReadFile(strings.TrimSpace(cfg.HMACSecretFile))
		if err != nil {
			return nil, fmt.Errorf("read hmac secret file: %w", err)
		}
		secret = strings.TrimSpace(string(raw))
	}
	if len(secret) < 32 {
		return nil, errors.New("INCARNATE_GATEWAY_HMAC_SECRET or INCARNATE_GATEWAY_HMAC_SECRET_FILE must provide at least 32 bytes")
	}
	return []byte(secret), nil
}

func proxyBrowserToJava(ctx context.Context, wsConn *websocket.Conn, javaConn net.Conn, maxFrameBytes int64) error {
	for {
		messageType, data, err := wsConn.Read(ctx)
		if err != nil {
			return err
		}
		if messageType != websocket.MessageText {
			return errors.New("websocket binary frames are not allowed")
		}
		if int64(len(data)) > maxFrameBytes {
			return errors.New("websocket frame too large")
		}
		if !json.Valid(data) {
			return errors.New("websocket frame must be json")
		}
		data = append(data, '\n')
		if _, err := javaConn.Write(data); err != nil {
			return err
		}
	}
}

func proxyJavaToBrowser(ctx context.Context, wsConn *websocket.Conn, javaReader *bufio.Reader, maxFrameBytes int64) error {
	max := int(maxFrameBytes)
	if max <= 0 {
		max = int(config.DefaultMaxFrameBytes)
	}
	for {
		line, err := readJavaLine(javaReader, max)
		if err != nil {
			return err
		}
		if !json.Valid(line) {
			return errors.New("java frame must be json")
		}
		if err := wsConn.Write(ctx, websocket.MessageText, line); err != nil {
			return err
		}
	}
}

func readJavaLine(reader *bufio.Reader, max int) ([]byte, error) {
	line, isPrefix, err := reader.ReadLine()
	if err != nil {
		return nil, err
	}
	if isPrefix || len(line) > max {
		return nil, errors.New("java frame too large")
	}
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return nil, errors.New("java frame empty")
	}
	return []byte(trimmed), nil
}

func (s *Server) clientIP(r *http.Request) string {
	peerIP := remoteIP(r.RemoteAddr)
	if s.trustsProxy(peerIP) {
		if headerIP := singleClientIPHeader(r.Header, s.cfg.ClientIPHeader); headerIP != "" {
			return headerIP
		}
	}
	return peerIP
}

func (s *Server) trustsProxy(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, proxy := range s.proxies {
		if proxy.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip.String()
		}
		return host
	}
	trimmed := strings.TrimSpace(remoteAddr)
	if trimmed == "" {
		return "unknown"
	}
	if ip, err := netip.ParseAddr(trimmed); err == nil {
		return ip.String()
	}
	return trimmed
}

func singleHeaderIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, ",") {
		return ""
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return ""
	}
	return ip.String()
}

func singleClientIPHeader(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return singleHeaderIP(values[0])
}

func parseProxyCIDRs(cidrs []string) ([]netip.Prefix, error) {
	proxies := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		proxy, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy cidr %q: %w", cidr, err)
		}
		proxies = append(proxies, proxy)
	}
	return proxies, nil
}
