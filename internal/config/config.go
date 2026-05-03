package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
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
	DefaultMaxFrameBytes           = 64 * 1024
)

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
}

func FromEnv() (Config, error) {
	cfg := Config{
		Bind:              getenv("INCARNATE_GATEWAY_BIND", DefaultBind),
		PublicOrigin:      getenv("INCARNATE_GATEWAY_PUBLIC_ORIGIN", DefaultPublicOrigin),
		AllowedOrigins:    splitCSV(getenv("INCARNATE_GATEWAY_ALLOWED_ORIGINS", DefaultPublicOrigin)),
		RPID:              getenv("INCARNATE_GATEWAY_RP_ID", DefaultRPID),
		RPName:            getenv("INCARNATE_GATEWAY_RP_NAME", DefaultRPName),
		JavaHost:          getenv("INCARNATE_GATEWAY_JAVA_HOST", DefaultJavaHost),
		JavaPort:          getenvInt("INCARNATE_GATEWAY_JAVA_PORT", DefaultJavaPort),
		GatewayID:         getenv("INCARNATE_GATEWAY_ID", DefaultGatewayID),
		HMACSecretFile:    os.Getenv("INCARNATE_GATEWAY_HMAC_SECRET_FILE"),
		SessionSecretFile: os.Getenv("INCARNATE_GATEWAY_SESSION_SECRET_FILE"),
		LogLevel:          getenv("INCARNATE_GATEWAY_LOG_LEVEL", "info"),
		SessionCookieName: getenv("INCARNATE_GATEWAY_SESSION_COOKIE_NAME", DefaultSessionCookieName),
		SessionTTL:        getenvDuration("INCARNATE_GATEWAY_SESSION_TTL", 12*time.Hour),
		SessionIdleTTL:    getenvDuration("INCARNATE_GATEWAY_SESSION_IDLE_TTL", 30*time.Minute),
		MaxBodyBytes:      int64(getenvInt("INCARNATE_GATEWAY_MAX_BODY_BYTES", int(DefaultMaxBodyBytes))),
		MaxFrameBytes:     int64(getenvInt("INCARNATE_GATEWAY_MAX_FRAME_BYTES", int(DefaultMaxFrameBytes))),
	}
	return cfg, cfg.Validate()
}

func (c Config) JavaAddress() string {
	return net.JoinHostPort(c.JavaHost, strconv.Itoa(c.JavaPort))
}

func (c Config) Validate() error {
	var errs []error
	if _, err := net.ResolveTCPAddr("tcp", c.Bind); err != nil {
		errs = append(errs, fmt.Errorf("invalid bind address: %w", err))
	}
	if err := validateOrigin(c.PublicOrigin); err != nil {
		errs = append(errs, fmt.Errorf("invalid public origin: %w", err))
	}
	if len(c.AllowedOrigins) == 0 {
		errs = append(errs, errors.New("at least one allowed origin is required"))
	}
	for _, origin := range c.AllowedOrigins {
		if err := validateOrigin(origin); err != nil {
			errs = append(errs, fmt.Errorf("invalid allowed origin %q: %w", origin, err))
		}
	}
	if strings.Contains(c.RPID, "://") || strings.TrimSpace(c.RPID) == "" {
		errs = append(errs, errors.New("rp id must be a bare domain"))
	}
	if strings.TrimSpace(c.RPName) == "" {
		errs = append(errs, errors.New("rp name is required"))
	}
	if c.JavaHost == "" || c.JavaPort <= 0 || c.JavaPort > 65535 {
		errs = append(errs, errors.New("java host and port are required"))
	}
	if strings.TrimSpace(c.GatewayID) == "" {
		errs = append(errs, errors.New("gateway id is required"))
	}
	if c.SessionTTL <= 0 || c.SessionIdleTTL <= 0 {
		errs = append(errs, errors.New("session ttl and idle ttl must be positive"))
	}
	if c.MaxBodyBytes <= 0 || c.MaxFrameBytes <= 0 {
		errs = append(errs, errors.New("body and frame limits must be positive"))
	}
	return errors.Join(errs...)
}

func validateOrigin(raw string) error {
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
	if u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("origin must include scheme and host only")
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return errors.New("plain http origins are limited to localhost development")
	}
	return nil
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return fallback
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
