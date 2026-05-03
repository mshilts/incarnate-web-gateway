package config

import (
	"strings"
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("INCARNATE_GATEWAY_BIND", "127.0.0.1:9000")
	t.Setenv("INCARNATE_GATEWAY_ALLOWED_ORIGINS", "https://play.inc-realm.com,http://127.0.0.1:5173")
	t.Setenv("INCARNATE_GATEWAY_RP_ID", "inc-realm.com")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv returned error: %v", err)
	}
	if cfg.Bind != "127.0.0.1:9000" {
		t.Fatalf("Bind = %q", cfg.Bind)
	}
	if got := cfg.JavaAddress(); got != "127.0.0.1:8083" {
		t.Fatalf("JavaAddress = %q", got)
	}
	if len(cfg.AllowedOrigins) != 2 {
		t.Fatalf("AllowedOrigins length = %d", len(cfg.AllowedOrigins))
	}
	if cfg.ClientIPHeader != DefaultClientIPHeader {
		t.Fatalf("ClientIPHeader = %q", cfg.ClientIPHeader)
	}
	if len(cfg.TrustedProxyCIDRs) != len(DefaultTrustedProxyCIDRs()) {
		t.Fatalf("TrustedProxyCIDRs length = %d", len(cfg.TrustedProxyCIDRs))
	}
}

func TestConfigRejectsWildcardOrigin(t *testing.T) {
	cfg := validTestConfig()
	cfg.AllowedOrigins = []string{"*"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted wildcard origin")
	}
}

func TestConfigFromEnvRejectsInvalidValues(t *testing.T) {
	t.Setenv("INCARNATE_GATEWAY_JAVA_PORT", "not-a-port")
	t.Setenv("INCARNATE_GATEWAY_SESSION_TTL", "forever")
	t.Setenv("INCARNATE_GATEWAY_MAX_BODY_BYTES", "huge")

	_, err := FromEnv()
	if err == nil {
		t.Fatal("FromEnv accepted invalid typed environment values")
	}
	for _, key := range []string{
		"INCARNATE_GATEWAY_JAVA_PORT",
		"INCARNATE_GATEWAY_SESSION_TTL",
		"INCARNATE_GATEWAY_MAX_BODY_BYTES",
	} {
		if !strings.Contains(err.Error(), key) {
			t.Fatalf("error does not identify %s: %v", key, err)
		}
	}
}

func TestConfigFromEnvRejectsEmptyTypedValue(t *testing.T) {
	t.Setenv("INCARNATE_GATEWAY_MAX_FRAME_BYTES", " ")

	_, err := FromEnv()
	if err == nil {
		t.Fatal("FromEnv accepted empty typed environment value")
	}
	if !strings.Contains(err.Error(), "INCARNATE_GATEWAY_MAX_FRAME_BYTES") {
		t.Fatalf("error does not identify bad env var: %v", err)
	}
}

func TestConfigRejectsPublicBindAndJavaHost(t *testing.T) {
	cfg := validTestConfig()
	cfg.Bind = "0.0.0.0:8789"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted public bind address")
	}

	cfg = validTestConfig()
	cfg.JavaHost = "10.0.0.5"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted non-loopback Java host")
	}
}

func TestConfigRejectsBadRPID(t *testing.T) {
	badIDs := []string{
		"https://inc-realm.com",
		"inc-realm.com/path",
		"*.inc-realm.com",
		"inc realm.com",
		"inc-realm",
		"Inc-Realm.com",
		"127.0.0.1",
	}
	for _, rpID := range badIDs {
		cfg := validTestConfig()
		cfg.RPID = rpID
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate accepted bad rp id %q", rpID)
		}
	}
}

func TestConfigRejectsInvalidOriginShape(t *testing.T) {
	badOrigins := []string{
		"https://user@play.inc-realm.com",
		"https://play.inc-realm.com?",
		" https://play.inc-realm.com",
		"http://play.inc-realm.com",
	}
	for _, origin := range badOrigins {
		cfg := validTestConfig()
		cfg.AllowedOrigins = []string{origin}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate accepted bad origin %q", origin)
		}
	}
}

func TestConfigRejectsInvalidClientIPTrustConfig(t *testing.T) {
	cfg := validTestConfig()
	cfg.ClientIPHeader = "Bad Header"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid client IP header name")
	}

	cfg = validTestConfig()
	cfg.TrustedProxyCIDRs = []string{"not-a-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid trusted proxy CIDR")
	}
}

func TestOriginAllowlist(t *testing.T) {
	allowlist, err := NewOriginAllowlist([]string{"https://play.inc-realm.com"})
	if err != nil {
		t.Fatalf("NewOriginAllowlist: %v", err)
	}
	if !allowlist.Allows("https://play.inc-realm.com") {
		t.Fatal("expected production origin to be allowed")
	}
	if allowlist.Allows("https://evil.example") {
		t.Fatal("unexpected origin allowed")
	}
}

func TestOriginAllowlistRejectsInvalidOrigin(t *testing.T) {
	if _, err := NewOriginAllowlist([]string{"https://play.inc-realm.com/path"}); err == nil {
		t.Fatal("NewOriginAllowlist accepted origin with path")
	}
}

func validTestConfig() Config {
	return Config{
		Bind:              DefaultBind,
		PublicOrigin:      DefaultPublicOrigin,
		AllowedOrigins:    []string{DefaultPublicOrigin},
		RPID:              DefaultRPID,
		RPName:            DefaultRPName,
		JavaHost:          DefaultJavaHost,
		JavaPort:          DefaultJavaPort,
		GatewayID:         DefaultGatewayID,
		SessionTTL:        1,
		SessionIdleTTL:    1,
		MaxBodyBytes:      1,
		MaxFrameBytes:     1,
		MaxHeaderBytes:    1,
		ClientIPHeader:    DefaultClientIPHeader,
		TrustedProxyCIDRs: DefaultTrustedProxyCIDRs(),
	}
}
