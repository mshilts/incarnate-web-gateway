package config

import "testing"

func TestSecurityConfigRejectsMalformedTypedEnv(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{name: "java-port-not-integer", key: "INCARNATE_GATEWAY_JAVA_PORT", value: "not-a-port"},
		{name: "java-port-zero", key: "INCARNATE_GATEWAY_JAVA_PORT", value: "0"},
		{name: "java-port-too-large", key: "INCARNATE_GATEWAY_JAVA_PORT", value: "65536"},
		{name: "session-ttl-not-duration", key: "INCARNATE_GATEWAY_SESSION_TTL", value: "forever"},
		{name: "session-ttl-zero", key: "INCARNATE_GATEWAY_SESSION_TTL", value: "0s"},
		{name: "session-idle-ttl-negative", key: "INCARNATE_GATEWAY_SESSION_IDLE_TTL", value: "-1s"},
		{name: "max-body-not-integer", key: "INCARNATE_GATEWAY_MAX_BODY_BYTES", value: "huge"},
		{name: "max-body-zero", key: "INCARNATE_GATEWAY_MAX_BODY_BYTES", value: "0"},
		{name: "max-frame-negative", key: "INCARNATE_GATEWAY_MAX_FRAME_BYTES", value: "-1"},
		{name: "max-header-zero", key: "INCARNATE_GATEWAY_MAX_HEADER_BYTES", value: "0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, err := FromEnv(); err == nil {
				t.Fatalf("FromEnv accepted %s=%q", tc.key, tc.value)
			}
		})
	}
}

func TestSecurityConfigRejectsPublicExposure(t *testing.T) {
	bindAddresses := []string{
		"0.0.0.0:8789",
		"[::]:8789",
		"192.0.2.10:8789",
	}
	for _, bind := range bindAddresses {
		t.Run("bind-"+bind, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.Bind = bind
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate accepted public bind %q", bind)
			}
		})
	}

	javaHosts := []string{
		"0.0.0.0",
		"::",
		"192.0.2.10",
		"game.inc-realm.com",
	}
	for _, host := range javaHosts {
		t.Run("java-"+host, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.JavaHost = host
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate accepted non-loopback Java host %q", host)
			}
		})
	}
}

func TestSecurityConfigRejectsOriginConfusion(t *testing.T) {
	cases := []struct {
		name   string
		origin string
	}{
		{name: "wildcard", origin: "*"},
		{name: "prefix-wildcard", origin: "https://*.inc-realm.com"},
		{name: "padded", origin: " https://play.inc-realm.com"},
		{name: "userinfo", origin: "https://attacker@play.inc-realm.com"},
		{name: "path", origin: "https://play.inc-realm.com/play"},
		{name: "empty-query", origin: "https://play.inc-realm.com?"},
		{name: "query", origin: "https://play.inc-realm.com?x=1"},
		{name: "fragment", origin: "https://play.inc-realm.com#frag"},
		{name: "non-loopback-http", origin: "http://play.inc-realm.com"},
		{name: "unsupported-scheme", origin: "wss://play.inc-realm.com"},
	}

	for _, tc := range cases {
		t.Run("public-"+tc.name, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.PublicOrigin = tc.origin
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate accepted public origin %q", tc.origin)
			}
		})

		t.Run("allowed-"+tc.name, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.AllowedOrigins = []string{tc.origin}
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate accepted allowed origin %q", tc.origin)
			}
		})
	}
}

func TestSecurityConfigRejectsRPIDConfusion(t *testing.T) {
	rpIDs := []string{
		"",
		" inc-realm.com",
		"https://inc-realm.com",
		"inc-realm.com/path",
		"*.inc-realm.com",
		"inc realm.com",
		"inc-realm",
		"Inc-Realm.com",
		"127.0.0.1",
		".inc-realm.com",
		"inc-realm.com.",
		"inc-realm..com",
		"-inc-realm.com",
		"inc-realm-.com",
	}

	for _, rpID := range rpIDs {
		t.Run(rpID, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.RPID = rpID
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate accepted rp id %q", rpID)
			}
		})
	}
}

func TestSecurityOriginAllowlistRejectsEmptyOrInvalidInput(t *testing.T) {
	cases := [][]string{
		nil,
		{},
		{"*"},
		{"https://play.inc-realm.com", "https://*.inc-realm.com"},
	}

	for _, origins := range cases {
		if _, err := NewOriginAllowlist(origins); err == nil {
			t.Fatalf("NewOriginAllowlist accepted %v", origins)
		}
	}
}
