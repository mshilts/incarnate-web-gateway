package config

import "testing"

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
}

func TestConfigRejectsWildcardOrigin(t *testing.T) {
	cfg := Config{
		Bind:           DefaultBind,
		PublicOrigin:   DefaultPublicOrigin,
		AllowedOrigins: []string{"*"},
		RPID:           DefaultRPID,
		RPName:         DefaultRPName,
		JavaHost:       DefaultJavaHost,
		JavaPort:       DefaultJavaPort,
		GatewayID:      DefaultGatewayID,
		SessionTTL:     1,
		SessionIdleTTL: 1,
		MaxBodyBytes:   1,
		MaxFrameBytes:  1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted wildcard origin")
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
