package javawire

import (
	"strings"
	"testing"
	"time"
)

func TestHMACCanonicalSigning(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	signer := Signer{
		GatewayID: "prod-play-gateway-1",
		Secret:    secret,
		Now:       func() time.Time { return time.UnixMilli(1777831034000) },
	}
	payload := map[string]any{
		"type":    "gateway_session_begin",
		"account": "matt",
		"nonce":   "fixed",
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := Verify(secret, signed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("signature did not verify")
	}
	signed["account"] = "mallory"
	ok, err = Verify(secret, signed)
	if err != nil {
		t.Fatalf("Verify tampered: %v", err)
	}
	if ok {
		t.Fatal("tampered payload verified")
	}
}

func TestHMACRejectsShortSecret(t *testing.T) {
	_, err := (Signer{GatewayID: "gw", Secret: []byte("short")}).Sign(map[string]any{"type": "x"})
	if err == nil {
		t.Fatal("Sign accepted short secret")
	}
}

func TestCanonicalPayloadSortsNestedStructFields(t *testing.T) {
	payload := map[string]any{
		"type":    "gateway_passkey_register",
		"account": "matt",
		"credential": Credential{
			Label:             "phone",
			Active:            true,
			CredentialID:      "Y3JlZA",
			PublicKeyCOSE:     "cHVibGlj",
			SignCount:         7,
			Transports:        []string{"internal"},
			RPID:              "localhost",
			Origin:            "http://localhost:4174",
			AllowedCharacters: []string{},
		},
	}
	canonical, err := CanonicalPayload(payload)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	text := string(canonical)
	if !strings.Contains(text, `"credential":{"active":true,"allowedCharacters":[],"credentialId":"Y3JlZA","label":"phone"`) {
		t.Fatalf("nested credential fields were not canonicalized: %s", text)
	}
}

func TestHMACVerifyRejectsShortSecret(t *testing.T) {
	ok, err := Verify([]byte("short"), map[string]any{"signature": "x"})
	if err == nil {
		t.Fatal("Verify accepted short secret")
	}
	if ok {
		t.Fatal("short secret verified")
	}
}
