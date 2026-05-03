package javawire

import (
	"strings"
	"testing"
	"time"
)

func TestSecurityHMACRejectsInvalidInputs(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	signer := Signer{
		GatewayID: "prod-play-gateway-1",
		Secret:    secret,
		Now:       func() time.Time { return time.UnixMilli(1777831034000) },
	}
	signed, err := signer.Sign(map[string]any{
		"type":    "gateway_session_begin",
		"account": "matt",
		"nonce":   "fixed",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	t.Run("missing-signature", func(t *testing.T) {
		payload := cloneMap(signed)
		delete(payload, "signature")
		ok, err := Verify(secret, payload)
		if err == nil {
			t.Fatal("Verify accepted missing signature")
		}
		if ok {
			t.Fatal("missing signature verified")
		}
	})

	t.Run("tampered-signature", func(t *testing.T) {
		payload := cloneMap(signed)
		payload["signature"] = "tampered"
		ok, err := Verify(secret, payload)
		if err != nil {
			t.Fatalf("Verify tampered signature: %v", err)
		}
		if ok {
			t.Fatal("tampered signature verified")
		}
	})

	t.Run("tampered-payload", func(t *testing.T) {
		payload := cloneMap(signed)
		payload["account"] = "mallory"
		ok, err := Verify(secret, payload)
		if err != nil {
			t.Fatalf("Verify tampered payload: %v", err)
		}
		if ok {
			t.Fatal("tampered payload verified")
		}
	})

	t.Run("wrong-secret", func(t *testing.T) {
		ok, err := Verify([]byte("abcdef0123456789abcdef0123456789"), signed)
		if err != nil {
			t.Fatalf("Verify wrong secret: %v", err)
		}
		if ok {
			t.Fatal("wrong secret verified")
		}
	})

	t.Run("short-verify-secret", func(t *testing.T) {
		ok, err := Verify([]byte("short"), signed)
		if err == nil {
			t.Fatal("Verify accepted short secret")
		}
		if ok {
			t.Fatal("short secret verified")
		}
	})
}

func TestSecurityHMACSignerRejectsWeakConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signer Signer
	}{
		{name: "missing-gateway-id", signer: Signer{Secret: []byte("0123456789abcdef0123456789abcdef")}},
		{name: "short-secret", signer: Signer{GatewayID: "gw", Secret: []byte("short")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.signer.Sign(map[string]any{"type": "x"}); err == nil {
				t.Fatal("Sign accepted weak configuration")
			}
		})
	}
}

func TestSecurityCanonicalPayloadDoesNotTrustProvidedSignature(t *testing.T) {
	payload := map[string]any{
		"type":      "gateway_session_begin",
		"account":   "matt",
		"signature": "attacker-controlled",
	}
	canonical, err := CanonicalPayload(payload)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if string(canonical) == "" {
		t.Fatal("canonical payload was empty")
	}
	if strings.Contains(string(canonical), "signature") {
		t.Fatal("canonical payload included attacker-controlled signature")
	}
}
