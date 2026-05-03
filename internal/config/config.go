package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultBind                    = "127.0.0.1:8789"
	DefaultPublicOrigin            = "https://play.inc-realm.com"
	DefaultRPID                    = "inc-realm.com"
	DefaultRPName                  = "Incarnate"
	DefaultJavaHost                = "127.0.0.1"
	DefaultJavaPort                = 8083
	DefaultGatewayID               = "dev-play-gateway-1"
	DefaultSessionCookieName       = "incarnate_gateway_session"
	DefaultMaxBodyBytes      int64 = 64 * 1024
	DefaultMaxFrameBytes     int64 = 64 * 1024
	DefaultMaxHeaderBytes          = 16 * 1024
	DefaultClientIPHeader          = "CF-Connecting-IP"
)

var errNoAllowedOrigins = errors.New("at least one allowed origin is required")

func DefaultTrustedProxyCIDRs() []string {
	return []string{"127.0.0.1/32", "::1/128"}
}

type Config struct {
	Bind              string
	PublicOrigin      string
	AllowedOrigins    []string
	RPID              string
	RPName            string
	JavaHost          string
	JavaPort          int
	GatewayID         string
	HMACSecretFile    string
	SessionSecretFile string
	LogLevel          string
	SessionCookieName string
	SessionTTL        time.Duration
	SessionIdleTTL    time.Duration
	MaxBodyBytes      int64
	MaxFrameBytes     int64
	MaxHeaderBytes    int
	ClientIPHeader    string
	TrustedProxyCIDRs []string
}

func FromEnv() (Config, error) {
	var errs []error
	javaPort, err := getenvInt("INCARNATE_GATEWAY_JAVA_PORT", DefaultJavaPort)
	if err != nil {
		errs = append(errs, err)
	}
	sessionTTL, err := getenvDuration("INCARNATE_GATEWAY_SESSION_TTL", 12*time.Hour)
	if err != nil {
		errs = append(errs, err)
	}
	sessionIdleTTL, err := getenvDuration("INCARNATE_GATEWAY_SESSION_IDLE_TTL", 30*time.Minute)
	if err != nil {
		errs = append(errs, err)
	}
	maxBodyBytes, err := getenvInt("INCARNATE_GATEWAY_MAX_BODY_BYTES", int(DefaultMaxBodyBytes))
	if err != nil {
		errs = append(errs, err)
	}
	maxFrameBytes, err := getenvInt("INCARNATE_GATEWAY_MAX_FRAME_BYTES", int(DefaultMaxFrameBytes))
	if err != nil {
		errs = append(errs, err)
	}
	maxHeaderBytes, err := getenvInt("INCARNATE_GATEWAY_MAX_HEADER_BYTES", DefaultMaxHeaderBytes)
	if err != nil {
		errs = append(errs, err)
	}
	cfg := Config{
		Bind:              getenv("INCARNATE_GATEWAY_BIND", DefaultBind),
		PublicOrigin:      getenv("INCARNATE_GATEWAY_PUBLIC_ORIGIN", DefaultPublicOrigin),
		AllowedOrigins:    splitCSV(getenv("INCARNATE_GATEWAY_ALLOWED_ORIGINS", DefaultPublicOrigin)),
		RPID:              getenv("INCARNATE_GATEWAY_RP_ID", DefaultRPID),
		RPName:            getenv("INCARNATE_GATEWAY_RP_NAME", DefaultRPName),
		JavaHost:          getenv("INCARNATE_GATEWAY_JAVA_HOST", DefaultJavaHost),
		JavaPort:          javaPort,
		GatewayID:         getenv("INCARNATE_GATEWAY_ID", DefaultGatewayID),
		HMACSecretFile:    os.Getenv("INCARNATE_GATEWAY_HMAC_SECRET_FILE"),
		SessionSecretFile: os.Getenv("INCARNATE_GATEWAY_SESSION_SECRET_FILE"),
		LogLevel:          getenv("INCARNATE_GATEWAY_LOG_LEVEL", "info"),
		SessionCookieName: getenv("INCARNATE_GATEWAY_SESSION_COOKIE_NAME", DefaultSessionCookieName),
		SessionTTL:        sessionTTL,
		SessionIdleTTL:    sessionIdleTTL,
		MaxBodyBytes:      int64(maxBodyBytes),
		MaxFrameBytes:     int64(maxFrameBytes),
		MaxHeaderBytes:    maxHeaderBytes,
		ClientIPHeader:    getenv("INCARNATE_GATEWAY_CLIENT_IP_HEADER", DefaultClientIPHeader),
		TrustedProxyCIDRs: getenvCSV("INCARNATE_GATEWAY_TRUSTED_PROXY_CIDRS", DefaultTrustedProxyCIDRs()),
	}
	if err := cfg.Validate(); err != nil {
		errs = append(errs, err)
	}
	return cfg, errors.Join(errs...)
}

func (c Config) JavaAddress() string {
	return net.JoinHostPort(c.JavaHost, strconv.Itoa(c.JavaPort))
}

func (c Config) Validate() error {
	var errs []error
	if _, err := net.ResolveTCPAddr("tcp", c.Bind); err != nil {
		errs = append(errs, fmt.Errorf("invalid bind address: %w", err))
	} else if err := validateLoopbackAddress(c.Bind); err != nil {
		errs = append(errs, fmt.Errorf("invalid bind address: %w", err))
	}
	if err := validateOrigin(c.PublicOrigin); err != nil {
		errs = append(errs, fmt.Errorf("invalid public origin: %w", err))
	}
	if err := validateOriginAllowlist(c.AllowedOrigins); err != nil {
		errs = append(errs, err)
	}
	if err := validateRPID(c.RPID); err != nil {
		errs = append(errs, fmt.Errorf("invalid rp id: %w", err))
	}
	if strings.TrimSpace(c.RPName) == "" {
		errs = append(errs, errors.New("rp name is required"))
	}
	if strings.TrimSpace(c.JavaHost) == "" || c.JavaPort <= 0 || c.JavaPort > 65535 {
		errs = append(errs, errors.New("java host and port are required"))
	} else if !isLoopbackHost(c.JavaHost) {
		errs = append(errs, errors.New("java host must be loopback"))
	}
	if strings.TrimSpace(c.GatewayID) == "" {
		errs = append(errs, errors.New("gateway id is required"))
	}
	if c.SessionTTL <= 0 || c.SessionIdleTTL <= 0 {
		errs = append(errs, errors.New("session ttl and idle ttl must be positive"))
	}
	if c.MaxBodyBytes <= 0 || c.MaxFrameBytes <= 0 || c.MaxHeaderBytes <= 0 {
		errs = append(errs, errors.New("body, frame, and header limits must be positive"))
	}
	if err := validateHeaderName(c.ClientIPHeader); err != nil {
		errs = append(errs, fmt.Errorf("invalid client ip header: %w", err))
	}
	for _, cidr := range c.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			errs = append(errs, fmt.Errorf("invalid trusted proxy cidr %q: %w", cidr, err))
		}
	}
	return errors.Join(errs...)
}

func validateOriginAllowlist(origins []string) error {
	var errs []error
	if len(origins) == 0 {
		errs = append(errs, errNoAllowedOrigins)
	}
	for _, origin := range origins {
		if err := validateOrigin(origin); err != nil {
			errs = append(errs, fmt.Errorf("invalid allowed origin %q: %w", origin, err))
		}
	}
	return errors.Join(errs...)
}

func validateOrigin(raw string) error {
	if raw != strings.TrimSpace(raw) || raw == "" {
		return errors.New("origin must not be empty or padded")
	}
	if raw == "*" || strings.Contains(raw, "*") {
		return errors.New("wildcard origins are not allowed")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("origin scheme must be http or https")
	}
	if u.User != nil {
		return errors.New("origin must not include user info")
	}
	if u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("origin must include scheme and host only")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return errors.New("plain http origins are limited to localhost development")
	}
	return nil
}

func validateRPID(rpID string) error {
	if rpID != strings.TrimSpace(rpID) || rpID == "" {
		return errors.New("rp id must not be empty or padded")
	}
	if rpID != strings.ToLower(rpID) {
		return errors.New("rp id must be lowercase")
	}
	if strings.Contains(rpID, "://") || strings.ContainsAny(rpID, "*/\\:@") || strings.ContainsFunc(rpID, unicode.IsSpace) {
		return errors.New("rp id must be a bare domain")
	}
	if rpID == "localhost" {
		return nil
	}
	if net.ParseIP(rpID) != nil {
		return errors.New("rp id must be a domain, not an IP address")
	}
	if len(rpID) > 253 || strings.HasPrefix(rpID, ".") || strings.HasSuffix(rpID, ".") || !strings.Contains(rpID, ".") {
		return errors.New("rp id must be a fully qualified domain without leading or trailing dots")
	}
	for _, label := range strings.Split(rpID, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("rp id contains an invalid domain label")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return errors.New("rp id contains an invalid domain character")
			}
		}
	}
	return nil
}

func validateHeaderName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("header name is required")
	}
	for _, r := range name {
		if r > 127 || !isHTTPTokenChar(r) {
			return errors.New("header name must be an HTTP token")
		}
	}
	return nil
}

func isHTTPTokenChar(r rune) bool {
	if r >= '0' && r <= '9' {
		return true
	}
	if r >= 'A' && r <= 'Z' {
		return true
	}
	if r >= 'a' && r <= 'z' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", r)
}

func validateLoopbackAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if !isLoopbackHost(host) {
		return errors.New("host must be loopback")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return fallback, nil
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return parsed, nil
}

func getenvDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return fallback, nil
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, fmt.Errorf("%s must be a duration", key)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration: %w", key, err)
	}
	return parsed, nil
}

func getenvCSV(key string, fallback []string) []string {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return append([]string(nil), fallback...)
	}
	return splitCSV(raw)
}

func splitCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
