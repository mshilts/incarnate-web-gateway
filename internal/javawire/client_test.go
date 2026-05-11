package javawire

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func TestClientLookupSignsAndParsesJavaResponse(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	client, requests := fakeJavaClient(t, secret, func(req map[string]any) map[string]any {
		return map[string]any{
			"type":    "gateway_passkey_lookup_result",
			"ok":      true,
			"account": req["account"],
			"credentials": []map[string]any{{
				"label":             "iphone",
				"credentialId":      "Y3JlZA",
				"publicKeyCose":     "cHVibGlj",
				"signCount":         7,
				"transports":        []string{"internal"},
				"rpId":              "inc-realm.com",
				"origin":            "https://play.inc-realm.com",
				"allowedCharacters": []string{},
			}},
		}
	})
	result, err := client.LookupPasskeys(context.Background(), "matt")
	if err != nil {
		t.Fatalf("LookupPasskeys: %v", err)
	}
	if result.Account != "matt" || len(result.Credentials) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	req := <-requests
	if req["type"] != "gateway_passkey_lookup" || req["gatewayId"] != "test-gateway" || req["signature"] == "" {
		t.Fatalf("request was not signed correctly: %+v", req)
	}
	ok, err := Verify(secret, req)
	if err != nil || !ok {
		t.Fatalf("signed request did not verify: ok=%v err=%v", ok, err)
	}
}

func TestClientSkipsJavaStartupFramesBeforeGatewayResult(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	client, _ := fakeJavaClientWithResponses(t, secret, func(req map[string]any) []map[string]any {
		return []map[string]any{
			{"type": "hello", "message": "Key authentication required."},
			{"type": "prompt", "promptType": "auth"},
			{
				"type":        "gateway_passkey_lookup_result",
				"ok":          true,
				"account":     req["account"],
				"credentials": []map[string]any{},
			},
		}
	})
	result, err := client.LookupPasskeys(context.Background(), "matt")
	if err != nil {
		t.Fatalf("LookupPasskeys: %v", err)
	}
	if result.Account != "matt" || len(result.Credentials) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestClientClaimPairingSignsAndParsesJavaResponse(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	client, requests := fakeJavaClient(t, secret, func(req map[string]any) map[string]any {
		return map[string]any{
			"type":     "gateway_pairing_claim_result",
			"ok":       true,
			"accepted": true,
			"account":  "matt",
		}
	})
	result, err := client.ClaimPairing(context.Background(), "opaque-token")
	if err != nil {
		t.Fatalf("ClaimPairing: %v", err)
	}
	if result.Account != "matt" {
		t.Fatalf("unexpected result: %+v", result)
	}
	req := <-requests
	if req["type"] != "gateway_pairing_claim" || req["pairingToken"] != "opaque-token" || req["signature"] == "" {
		t.Fatalf("request was not signed correctly: %+v", req)
	}
}

func TestClientSignupPasskeySignsAndParsesJavaResponse(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	client, requests := fakeJavaClient(t, secret, func(req map[string]any) map[string]any {
		return map[string]any{
			"type":    "gateway_passkey_signup_result",
			"ok":      true,
			"account": req["account"],
			"label":   req["label"],
		}
	})
	credential := Credential{
		Label:             "phone",
		CredentialID:      "Y3JlZA",
		PublicKeyCOSE:     "cHVibGlj",
		SignCount:         1,
		Transports:        []string{"internal"},
		RPID:              "inc-realm.com",
		Origin:            "https://play.inc-realm.com",
		AllowedCharacters: []string{},
	}
	result, err := client.SignupPasskey(context.Background(), "new_player", "phone", credential)
	if err != nil {
		t.Fatalf("SignupPasskey: %v", err)
	}
	if result.Account != "new_player" || result.Label != "phone" {
		t.Fatalf("unexpected result: %+v", result)
	}
	req := <-requests
	if req["type"] != "gateway_passkey_signup" || req["account"] != "new_player" || req["signature"] == "" {
		t.Fatalf("request was not signed correctly: %+v", req)
	}
}

func TestClientFailsClosedOnMismatchedTypeRejectedAndOversize(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	for _, tc := range []struct {
		name      string
		maxLine   int
		response  func(map[string]any) map[string]any
		wantError error
	}{
		{
			name: "mismatched-type",
			response: func(map[string]any) map[string]any {
				return map[string]any{"type": "wrong_result", "ok": true}
			},
			wantError: ErrProtocol,
		},
		{
			name: "ok-false",
			response: func(map[string]any) map[string]any {
				return map[string]any{"type": "gateway_passkey_lookup_result", "ok": false}
			},
			wantError: ErrRejected,
		},
		{
			name:    "oversize",
			maxLine: 16,
			response: func(map[string]any) map[string]any {
				return map[string]any{"type": "gateway_passkey_lookup_result", "ok": true, "padding": "this is too long"}
			},
			wantError: ErrProtocol,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := fakeJavaClient(t, secret, tc.response)
			if tc.maxLine > 0 {
				client.MaxLine = tc.maxLine
			}
			if _, err := client.LookupPasskeys(context.Background(), "matt"); !errors.Is(err, tc.wantError) {
				t.Fatalf("error = %v, want %v", err, tc.wantError)
			}
		})
	}
}

func fakeJavaClient(t *testing.T, secret []byte, response func(map[string]any) map[string]any) (Client, <-chan map[string]any) {
	return fakeJavaClientWithResponses(t, secret, func(req map[string]any) []map[string]any {
		return []map[string]any{response(req)}
	})
}

func fakeJavaClientWithResponses(t *testing.T, secret []byte, response func(map[string]any) []map[string]any) (Client, <-chan map[string]any) {
	t.Helper()
	requests := make(chan map[string]any, 1)
	client := Client{
		Addr:    "fake",
		Timeout: time.Second,
		Signer: Signer{
			GatewayID: "test-gateway",
			Secret:    secret,
			Now:       func() time.Time { return time.UnixMilli(1777831034000) },
		},
		NonceFunc: func() (string, error) { return "nonce-1234567890123456", nil },
		Dialer: func(context.Context, string) (net.Conn, error) {
			server, gateway := net.Pipe()
			go func() {
				defer server.Close()
				line, err := bufio.NewReader(server).ReadBytes('\n')
				if err != nil {
					return
				}
				var req map[string]any
				if err := json.Unmarshal(line, &req); err != nil {
					return
				}
				requests <- req
				for _, payload := range response(req) {
					encoded, _ := json.Marshal(payload)
					encoded = append(encoded, '\n')
					_, _ = server.Write(encoded)
				}
			}()
			return gateway, nil
		},
	}
	return client, requests
}
