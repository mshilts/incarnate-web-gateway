package passkeys

import (
	"context"
	"testing"

	"github.com/mshilts/incarnate-web-gateway/internal/javawire"
)

func TestRegistrationOptionsRequiresExplicitAccountUntilPairingClaimExists(t *testing.T) {
	service := testWebAuthnService(t, fakeJava{})
	if _, err := service.RegistrationOptions(context.Background(), RegistrationOptionsRequest{
		PairingToken: "opaque-token",
		Label:        "iphone",
	}); err == nil {
		t.Fatal("RegistrationOptions accepted opaque pairing token without Java pairing claim support")
	}
}

func TestRegistrationOptionsAcceptsLocalAccountToken(t *testing.T) {
	service := testWebAuthnService(t, fakeJava{})
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
}

func TestLoginOptionsUsesJavaCredentialLookup(t *testing.T) {
	service := testWebAuthnService(t, fakeJava{credentials: []javawire.Credential{{
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

func testWebAuthnService(t *testing.T, java fakeJava) *WebAuthnService {
	t.Helper()
	service, err := NewWebAuthnService(ServiceConfig{
		RPID:           "localhost",
		RPName:         "Incarnate Test",
		AllowedOrigins: []string{"http://localhost:8789"},
	}, java)
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	return service
}

type fakeJava struct {
	credentials []javawire.Credential
}

func (f fakeJava) LookupPasskeys(context.Context, string) (javawire.LookupResult, error) {
	return javawire.LookupResult{Type: "gateway_passkey_lookup_result", OK: true, Account: "matt", Credentials: f.credentials}, nil
}

func (f fakeJava) RegisterPasskey(context.Context, string, string, javawire.Credential) (javawire.RegisterResult, error) {
	return javawire.RegisterResult{Type: "gateway_passkey_register_result", OK: true, Account: "matt", Label: "iphone"}, nil
}

func (f fakeJava) UpdateCounter(context.Context, string, string, uint32) (javawire.CounterResult, error) {
	return javawire.CounterResult{Type: "gateway_passkey_counter_result", OK: true}, nil
}
