package passkeys

import (
	"context"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
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

func TestSignupOptionsRejectsExistingAccount(t *testing.T) {
	service := testWebAuthnService(t, &fakeJava{})
	_, err := service.SignupOptions(context.Background(), SignupOptionsRequest{
		Account: "existing_player",
		Label:   "iphone",
	})
	if !errors.Is(err, ErrAccountTaken) {
		t.Fatalf("SignupOptions error = %v, want %v", err, ErrAccountTaken)
	}
	if got := PublicErrorMessage(err, "fallback"); got != AccountTakenMessage {
		t.Fatalf("PublicErrorMessage = %q", got)
	}
}

func TestSignupOptionsStartsRegistrationForNewNormalAccount(t *testing.T) {
	java := &fakeJava{lookupErr: javawire.ErrRejected}
	service := testWebAuthnService(t, java)
	response, err := service.SignupOptions(context.Background(), SignupOptionsRequest{
		Account: "new_player",
		Label:   "phone",
	})
	if err != nil {
		t.Fatalf("SignupOptions: %v", err)
	}
	if response["registrationId"] == "" || response["publicKey"] == nil || response["account"] != "new_player" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if java.lookupAccount != "new_player" {
		t.Fatalf("LookupPasskeys account = %q", java.lookupAccount)
	}
}

func TestSignupOptionsRejectsReservedOrUnsafeAccountNames(t *testing.T) {
	service := testWebAuthnService(t, &fakeJava{lookupErr: javawire.ErrRejected})
	for _, account := range []string{"admin", "root", "ai_pool_1", "../bad", "ab"} {
		t.Run(account, func(t *testing.T) {
			_, err := service.SignupOptions(context.Background(), SignupOptionsRequest{
				Account: account,
				Label:   "phone",
			})
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("SignupOptions error = %v, want %v", err, ErrRejected)
			}
		})
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

func TestDiscoverableLoginOptionsUseEmptyAllowCredentials(t *testing.T) {
	java := &fakeJava{lookupErr: errors.New("lookup should not be called")}
	service := testWebAuthnService(t, java)
	response, err := service.LoginOptions(context.Background(), LoginOptionsRequest{})
	if err != nil {
		t.Fatalf("LoginOptions: %v", err)
	}
	if response["loginId"] == "" || response["publicKey"] == nil {
		t.Fatalf("unexpected response: %+v", response)
	}
	publicKey, ok := response["publicKey"].(protocol.PublicKeyCredentialRequestOptions)
	if !ok {
		t.Fatalf("publicKey type = %T", response["publicKey"])
	}
	if len(publicKey.AllowedCredentials) != 0 {
		t.Fatalf("AllowedCredentials = %+v, want empty", publicKey.AllowedCredentials)
	}
	if publicKey.UserVerification != protocol.VerificationRequired {
		t.Fatalf("UserVerification = %q", publicKey.UserVerification)
	}
	if java.lookupAccount != "" {
		t.Fatalf("LookupPasskeys account = %q", java.lookupAccount)
	}
}

func TestDiscoverableUserLooksUpAccountFromUserHandleAndRequiresRawCredentialID(t *testing.T) {
	service := testWebAuthnService(t, &fakeJava{credentials: []javawire.Credential{{
		Label:         "iphone",
		Active:        true,
		CredentialID:  "Y3JlZA",
		PublicKeyCOSE: "cHVibGlj",
		SignCount:     1,
		Transports:    []string{"internal"},
		RPID:          "localhost",
		Origin:        "http://localhost:8789",
	}}})
	user, err := service.discoverableUser(context.Background(), []byte("cred"), []byte("matt"))
	if err != nil {
		t.Fatalf("discoverableUser: %v", err)
	}
	javaUser, ok := user.(javaUser)
	if !ok {
		t.Fatalf("user type = %T", user)
	}
	if javaUser.account != "matt" {
		t.Fatalf("account = %q", javaUser.account)
	}
}

func TestDiscoverableUserRejectsUnsafeOrUnownedCredentials(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rawID      []byte
		userHandle []byte
		java       *fakeJava
	}{
		{
			name:       "blank-user-handle",
			rawID:      []byte("cred"),
			userHandle: nil,
			java:       &fakeJava{},
		},
		{
			name:       "unsafe-user-handle",
			rawID:      []byte("cred"),
			userHandle: []byte("../bad"),
			java:       &fakeJava{},
		},
		{
			name:       "java-rejected",
			rawID:      []byte("cred"),
			userHandle: []byte("matt"),
			java:       &fakeJava{lookupErr: javawire.ErrRejected},
		},
		{
			name:       "credential-not-owned",
			rawID:      []byte("other"),
			userHandle: []byte("matt"),
			java: &fakeJava{credentials: []javawire.Credential{{
				Active:       true,
				CredentialID: "Y3JlZA",
			}}},
		},
		{
			name:       "inactive-credential",
			rawID:      []byte("cred"),
			userHandle: []byte("matt"),
			java: &fakeJava{credentials: []javawire.Credential{{
				Active:       false,
				CredentialID: "Y3JlZA",
			}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := testWebAuthnService(t, tc.java)
			if _, err := service.discoverableUser(context.Background(), tc.rawID, tc.userHandle); err == nil {
				t.Fatal("discoverableUser accepted invalid credential")
			}
		})
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
	credentials   []javawire.Credential
	claimAccount  string
	claimErr      error
	claimedToken  string
	lookupErr     error
	lookupAccount string
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

func (f *fakeJava) LookupPasskeys(_ context.Context, account string) (javawire.LookupResult, error) {
	f.lookupAccount = account
	if f.lookupErr != nil {
		return javawire.LookupResult{}, f.lookupErr
	}
	return javawire.LookupResult{Type: "gateway_passkey_lookup_result", OK: true, Account: account, Credentials: f.credentials}, nil
}

func (f *fakeJava) RegisterPasskey(context.Context, string, string, javawire.Credential) (javawire.RegisterResult, error) {
	return javawire.RegisterResult{Type: "gateway_passkey_register_result", OK: true, Account: "matt", Label: "iphone"}, nil
}

func (f *fakeJava) SignupPasskey(_ context.Context, account, label string, _ javawire.Credential) (javawire.RegisterResult, error) {
	return javawire.RegisterResult{Type: "gateway_passkey_signup_result", OK: true, Account: account, Label: label}, nil
}

func (f *fakeJava) UpdateCounter(context.Context, string, string, uint32) (javawire.CounterResult, error) {
	return javawire.CounterResult{Type: "gateway_passkey_counter_result", OK: true}, nil
}
