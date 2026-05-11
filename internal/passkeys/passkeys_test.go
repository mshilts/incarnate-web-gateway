package passkeys

import (
	"context"
	"errors"
	"testing"

	"github.com/mshilts/incarnate-web-gateway/internal/javawire"
)

func TestRegistrationOptionsClaimsOpaquePairingTokenFromJava(t *testing.T) {
	java := &fakeJava{claimAccount: "matt"}
	service := testWebAuthnService(t, java)
	response, err := service.RegistrationOptions(context.Background(), RegistrationOptionsRequest{
		PairingToken: "opaque-token",
		Label:        "iphone",
	})
	if err != nil {
		t.Fatalf("RegistrationOptions: %v", err)
	}
	if response["registrationId"] == "" || response["publicKey"] == nil || response["account"] != "matt" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if java.claimedToken != "opaque-token" {
		t.Fatalf("ClaimPairing token = %q", java.claimedToken)
	}
}

func TestRegistrationOptionsRejectsLocalAccountTokenWhenFallbackDisabled(t *testing.T) {
	java := &fakeJava{claimErr: javawire.ErrRejected}
	service := testWebAuthnService(t, java)
	_, err := service.RegistrationOptions(context.Background(), RegistrationOptionsRequest{
		PairingToken: "account:matt",
		Label:        "iphone",
	})
	if !errors.Is(err, javawire.ErrRejected) {
		t.Fatalf("RegistrationOptions error = %v, want %v", err, javawire.ErrRejected)
	}
	if java.claimedToken != "account:matt" {
		t.Fatalf("ClaimPairing token = %q", java.claimedToken)
	}
}

func TestRegistrationOptionsAcceptsLocalAccountTokenOnlyWhenConfigured(t *testing.T) {
	java := &fakeJava{claimErr: errors.New("claim should not be called")}
	service := testWebAuthnService(t, java, func(cfg *ServiceConfig) {
		cfg.AllowLocalAccountPairing = true
	})
	response, err := service.RegistrationOptions(context.Background(), RegistrationOptionsRequest{
		PairingToken: "account:matt",
		Label:        "iphone",
	})
	if err != nil {
		t.Fatalf("RegistrationOptions: %v", err)
	}
	if response["registrationId"] == "" || response["publicKey"] == nil || response["account"] != "matt" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if java.claimedToken != "" {
		t.Fatalf("ClaimPairing was called for local account token: %q", java.claimedToken)
	}
}

func TestLoginOptionsUsesJavaCredentialLookup(t *testing.T) {
	service := testWebAuthnService(t, &fakeJava{credentials: []javawire.Credential{{
		Label:             "iphone",
		CredentialID:      "Y3JlZA",
		PublicKeyCOSE:     "cHVibGlj",
		SignCount:         1,
		Transports:        []string{"internal"},
		RPID:              "localhost",
		Origin:            "http://localhost:8789",
		AllowedCharacters: []string{},
	}}})
	response, err := service.LoginOptions(context.Background(), LoginOptionsRequest{Account: "matt"})
	if err != nil {
		t.Fatalf("LoginOptions: %v", err)
	}
	if response["loginId"] == "" || response["publicKey"] == nil {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func testWebAuthnService(t *testing.T, java *fakeJava, options ...func(*ServiceConfig)) *WebAuthnService {
	t.Helper()
	cfg := ServiceConfig{
		RPID:           "localhost",
		RPName:         "Incarnate Test",
		AllowedOrigins: []string{"http://localhost:8789"},
	}
	for _, option := range options {
		option(&cfg)
	}
	service, err := NewWebAuthnService(cfg, java)
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	return service
}

type fakeJava struct {
	credentials  []javawire.Credential
	claimAccount string
	claimErr     error
	claimedToken string
}

func (f *fakeJava) ClaimPairing(_ context.Context, token string) (javawire.PairingClaimResult, error) {
	f.claimedToken = token
	if f.claimErr != nil {
		return javawire.PairingClaimResult{}, f.claimErr
	}
	account := f.claimAccount
	if account == "" {
		account = "matt"
	}
	return javawire.PairingClaimResult{Type: "gateway_pairing_claim_result", OK: true, Account: account}, nil
}

func (f *fakeJava) LookupPasskeys(context.Context, string) (javawire.LookupResult, error) {
	return javawire.LookupResult{Type: "gateway_passkey_lookup_result", OK: true, Account: "matt", Credentials: f.credentials}, nil
}

func (f *fakeJava) RegisterPasskey(context.Context, string, string, javawire.Credential) (javawire.RegisterResult, error) {
	return javawire.RegisterResult{Type: "gateway_passkey_register_result", OK: true, Account: "matt", Label: "iphone"}, nil
}

func (f *fakeJava) UpdateCounter(context.Context, string, string, uint32) (javawire.CounterResult, error) {
	return javawire.CounterResult{Type: "gateway_passkey_counter_result", OK: true}, nil
}
