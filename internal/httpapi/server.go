package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/mshilts/incarnate-web-gateway/internal/audit"
	"github.com/mshilts/incarnate-web-gateway/internal/config"
	"github.com/mshilts/incarnate-web-gateway/internal/passkeys"
	"github.com/mshilts/incarnate-web-gateway/internal/ratelimit"
	"github.com/mshilts/incarnate-web-gateway/internal/session"
)

type Server struct {
	cfg       config.Config
	origins   config.OriginAllowlist
	passkeys  passkeys.Service
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
	return &Server{
		cfg:       cfg,
		origins:   origins,
		passkeys:  passkeys.PlaceholderService{},
		sessions:  session.NewStore(cfg.SessionTTL, cfg.SessionIdleTTL),
		authLimit: ratelimit.New(20, time.Minute),
		audit:     audit.New(logger),
		proxies:   proxies,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("POST /auth/passkey/login/options", s.loginOptions)
	mux.HandleFunc("POST /auth/passkey/login/verify", s.loginVerify)
	mux.HandleFunc("POST /auth/passkey/register/options", s.registerOptions)
	mux.HandleFunc("POST /auth/passkey/register/verify", s.registerVerify)
	mux.HandleFunc("GET /play/ws", s.playWS)
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
	_, err := s.passkeys.LoginOptions(r.Context(), req)
	if errors.Is(err, passkeys.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "passkey login options are not implemented in v0.1")
		return
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "login options rejected")
		return
	}
}

func (s *Server) loginVerify(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrigin(w, r) || !s.requireRateLimit(w, r, "login-verify") {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var req map[string]any
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.passkeys.LoginVerify(r.Context(), req); errors.Is(err, passkeys.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "passkey login verify is not implemented in v0.1")
		return
	} else if err != nil {
		writeError(w, http.StatusUnauthorized, "login verify rejected")
		return
	}
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
	if _, err := s.passkeys.RegistrationOptions(r.Context(), req); errors.Is(err, passkeys.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "passkey registration options are not implemented in v0.1")
		return
	} else if err != nil {
		writeError(w, http.StatusUnauthorized, "registration options rejected")
		return
	}
}

func (s *Server) registerVerify(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrigin(w, r) || !s.requireRateLimit(w, r, "register-verify") {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var req map[string]any
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.passkeys.RegistrationVerify(r.Context(), req); errors.Is(err, passkeys.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "passkey registration verify is not implemented in v0.1")
		return
	} else if err != nil {
		writeError(w, http.StatusUnauthorized, "registration verify rejected")
		return
	}
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
	if _, err := s.sessions.Get(cookie.Value); err != nil {
		writeError(w, http.StatusUnauthorized, "valid session is required")
		return
	}
	if r.ContentLength != 0 {
		writeError(w, http.StatusBadRequest, "websocket upgrade must not include a request body")
		return
	}
	writeError(w, http.StatusNotImplemented, "websocket proxy is not implemented in v0.1")
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
	return true
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": message})
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
