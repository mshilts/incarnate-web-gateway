package passkeys

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mshilts/incarnate-web-gateway/internal/javawire"
)

var ErrNotImplemented = errors.New("passkey ceremonies are placeholders in v0.1")

var (
	ErrNotFound     = errors.New("passkey ceremony not found")
	ErrRejected     = errors.New("passkey ceremony rejected")
	ErrAccountTaken = errors.New("account already taken")
)

const AccountTakenMessage = "Account already taken."

func PublicErrorMessage(err error, fallback string) string {
	if errors.Is(err, ErrAccountTaken) {
		return AccountTakenMessage
	}
	switch message := javawire.RejectionMessage(err); message {
	case AccountTakenMessage, "Account already exists.":
		return AccountTakenMessage
	case "That account name is reserved.", "Unsafe account name.":
		return message
	}
	return fallback
}

type JavaClient interface {
	ClaimPairing(context.Context, string) (javawire.PairingClaimResult, error)
	LookupPasskeys(context.Context, string) (javawire.LookupResult, error)
	RegisterPasskey(context.Context, string, string, javawire.Credential) (javawire.RegisterResult, error)
	SignupPasskey(context.Context, string, string, javawire.Credential) (javawire.RegisterResult, error)
	UpdateCounter(context.Context, string, string, uint32) (javawire.CounterResult, error)
}

type LoginOptionsRequest struct {
	Account string `json:"account"`
}

type LoginVerifyRequest struct {
	LoginID  string          `json:"loginId"`
	Response json.RawMessage `json:"response"`
}

type RegistrationOptionsRequest struct {
	PairingToken string `json:"pairingToken"`
	Label        string `json:"label"`
}

type RegistrationVerifyRequest struct {
	RegistrationID string          `json:"registrationId"`
	Response       json.RawMessage `json:"response"`
}

type SignupOptionsRequest struct {
	Account string `json:"account"`
	Label   string `json:"label"`
}

type SignupVerifyRequest struct {
	RegistrationID string          `json:"registrationId"`
	Response       json.RawMessage `json:"response"`
}

type AuthenticatedCredential struct {
	Account         string
	CredentialID    string
	CredentialLabel string
}

type Service interface {
	LoginOptions(context.Context, LoginOptionsRequest) (map[string]any, error)
	LoginVerify(context.Context, LoginVerifyRequest) (AuthenticatedCredential, error)
	RegistrationOptions(context.Context, RegistrationOptionsRequest) (map[string]any, error)
	RegistrationVerify(context.Context, RegistrationVerifyRequest) (AuthenticatedCredential, error)
	SignupOptions(context.Context, SignupOptionsRequest) (map[string]any, error)
	SignupVerify(context.Context, SignupVerifyRequest) (AuthenticatedCredential, error)
}

type ServiceConfig struct {
	RPID                     string
	RPName                   string
	AllowedOrigins           []string
	TTL                      time.Duration
	AllowLocalAccountPairing bool
}

type WebAuthnService struct {
	webAuthn                 *webauthnlib.WebAuthn
	java                     JavaClient
	ttl                      time.Duration
	allowLocalAccountPairing bool
	now                      func() time.Time

	mu            sync.Mutex
	loginPending  map[string]loginCeremony
	regPending    map[string]registrationCeremony
	nextPruneTime time.Time
}

type loginCeremony struct {
	Account      string
	Credentials  []javawire.Credential
	Session      webauthnlib.SessionData
	ExpiresAt    time.Time
	Discoverable bool
}

type registrationCeremony struct {
	Account   string
	Label     string
	Session   webauthnlib.SessionData
	ExpiresAt time.Time
	Signup    bool
}

func NewWebAuthnService(cfg ServiceConfig, java JavaClient) (*WebAuthnService, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	webAuthn, err := webauthnlib.New(&webauthnlib.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPName,
		RPOrigins:     cfg.AllowedOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, err
	}
	return &WebAuthnService{
		webAuthn:                 webAuthn,
		java:                     java,
		ttl:                      cfg.TTL,
		allowLocalAccountPairing: cfg.AllowLocalAccountPairing,
		now:                      time.Now,
		loginPending:             make(map[string]loginCeremony),
		regPending:               make(map[string]registrationCeremony),
	}, nil
}

func (s *WebAuthnService) LoginOptions(ctx context.Context, req LoginOptionsRequest) (map[string]any, error) {
	account := strings.TrimSpace(req.Account)
	if account == "" {
		return s.discoverableLoginOptions()
	}
	return s.accountLoginOptions(ctx, account)
}

func (s *WebAuthnService) discoverableLoginOptions() (map[string]any, error) {
	assertion, session, err := s.webAuthn.BeginDiscoverableMediatedLogin(
		protocol.MediationConditional,
		webauthnlib.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.pruneLocked()
	s.loginPending[id] = loginCeremony{
		Session:      *session,
		ExpiresAt:    s.now().Add(s.ttl),
		Discoverable: true,
	}
	s.mu.Unlock()
	return map[string]any{
		"ok":        true,
		"publicKey": assertion.Response,
		"loginId":   id,
	}, nil
}

func (s *WebAuthnService) accountLoginOptions(ctx context.Context, account string) (map[string]any, error) {
	if account == "" {
		return nil, ErrRejected
	}
	lookup, err := s.java.LookupPasskeys(ctx, account)
	if err != nil {
		return nil, err
	}
	if len(lookup.Credentials) == 0 {
		return nil, ErrRejected
	}
	user := javaUser{account: account, credentials: lookup.Credentials}
	assertion, session, err := s.webAuthn.BeginLogin(user, webauthnlib.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.pruneLocked()
	s.loginPending[id] = loginCeremony{
		Account:     account,
		Credentials: lookup.Credentials,
		Session:     *session,
		ExpiresAt:   s.now().Add(s.ttl),
	}
	s.mu.Unlock()
	return map[string]any{
		"ok":        true,
		"publicKey": assertion.Response,
		"loginId":   id,
	}, nil
}

func (s *WebAuthnService) LoginVerify(ctx context.Context, req LoginVerifyRequest) (AuthenticatedCredential, error) {
	if strings.TrimSpace(req.LoginID) == "" || len(req.Response) == 0 {
		return AuthenticatedCredential{}, ErrRejected
	}
	ceremony, err := s.takeLogin(req.LoginID)
	if err != nil {
		return AuthenticatedCredential{}, err
	}
	if ceremony.Discoverable {
		return s.finishDiscoverableLogin(ctx, ceremony, req.Response)
	}
	user := javaUser{account: ceremony.Account, credentials: ceremony.Credentials}
	credential, err := s.webAuthn.FinishLogin(user, ceremony.Session, rawCredentialRequest(req.Response))
	if err != nil {
		return AuthenticatedCredential{}, err
	}
	credentialID := javawire.EncodeBase64URL(credential.ID)
	label := labelForCredential(ceremony.Credentials, credentialID)
	if _, err := s.java.UpdateCounter(ctx, ceremony.Account, credentialID, credential.Authenticator.SignCount); err != nil {
		return AuthenticatedCredential{}, err
	}
	return AuthenticatedCredential{Account: ceremony.Account, CredentialID: credentialID, CredentialLabel: label}, nil
}

func (s *WebAuthnService) finishDiscoverableLogin(ctx context.Context, ceremony loginCeremony, response json.RawMessage) (AuthenticatedCredential, error) {
	var resolved javaUser
	handler := func(rawID, userHandle []byte) (webauthnlib.User, error) {
		user, err := s.discoverableUser(ctx, rawID, userHandle)
		if err != nil {
			return nil, err
		}
		javaUser, ok := user.(javaUser)
		if !ok {
			return nil, ErrRejected
		}
		resolved = javaUser
		return resolved, nil
	}
	user, credential, err := s.webAuthn.FinishPasskeyLogin(handler, ceremony.Session, rawCredentialRequest(response))
	if err != nil {
		return AuthenticatedCredential{}, err
	}
	account := strings.TrimSpace(user.WebAuthnName())
	if account == "" {
		return AuthenticatedCredential{}, ErrRejected
	}
	credentialID := javawire.EncodeBase64URL(credential.ID)
	label := labelForCredential(resolved.credentials, credentialID)
	if _, err := s.java.UpdateCounter(ctx, account, credentialID, credential.Authenticator.SignCount); err != nil {
		return AuthenticatedCredential{}, err
	}
	return AuthenticatedCredential{Account: account, CredentialID: credentialID, CredentialLabel: label}, nil
}

func (s *WebAuthnService) discoverableUser(ctx context.Context, rawID, userHandle []byte) (webauthnlib.User, error) {
	account, err := normalizeLoginAccount(string(userHandle))
	if err != nil {
		return nil, ErrRejected
	}
	lookup, err := s.java.LookupPasskeys(ctx, account)
	if err != nil {
		return nil, err
	}
	if len(lookup.Credentials) == 0 {
		return nil, ErrRejected
	}
	credentialID := javawire.EncodeBase64URL(rawID)
	for _, credential := range lookup.Credentials {
		if credential.Active && credential.CredentialID == credentialID {
			return javaUser{account: account, credentials: lookup.Credentials}, nil
		}
	}
	return nil, ErrRejected
}

func (s *WebAuthnService) RegistrationOptions(ctx context.Context, req RegistrationOptionsRequest) (map[string]any, error) {
	account, err := s.registrationAccount(ctx, req.PairingToken)
	if err != nil {
		return nil, err
	}
	label, err := normalizePasskeyLabel(req.Label)
	if err != nil || account == "" {
		return nil, ErrRejected
	}
	lookup, err := s.java.LookupPasskeys(ctx, account)
	if err != nil {
		return nil, err
	}
	return s.beginRegistration(account, label, lookup.Credentials, false)
}

func (s *WebAuthnService) SignupOptions(ctx context.Context, req SignupOptionsRequest) (map[string]any, error) {
	account, err := normalizeSignupAccount(req.Account)
	if err != nil {
		return nil, ErrRejected
	}
	label, err := normalizePasskeyLabel(req.Label)
	if err != nil {
		return nil, ErrRejected
	}
	if _, err := s.java.LookupPasskeys(ctx, account); err == nil {
		return nil, ErrAccountTaken
	} else if !errors.Is(err, javawire.ErrRejected) {
		return nil, err
	} else if message := javawire.RejectionMessage(err); message != "" && message != "Unknown account." {
		return nil, ErrAccountTaken
	}
	return s.beginRegistration(account, label, nil, true)
}

func (s *WebAuthnService) beginRegistration(account, label string, credentials []javawire.Credential, signup bool) (map[string]any, error) {
	user := javaUser{account: account, credentials: credentials}
	creation, session, err := s.webAuthn.BeginRegistration(user,
		webauthnlib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.pruneLocked()
	s.regPending[id] = registrationCeremony{
		Account:   account,
		Label:     label,
		Session:   *session,
		ExpiresAt: s.now().Add(s.ttl),
		Signup:    signup,
	}
	s.mu.Unlock()
	return map[string]any{
		"ok":             true,
		"account":        account,
		"publicKey":      creation.Response,
		"registrationId": id,
	}, nil
}

func (s *WebAuthnService) RegistrationVerify(ctx context.Context, req RegistrationVerifyRequest) (AuthenticatedCredential, error) {
	return s.finishRegistration(ctx, req.RegistrationID, req.Response)
}

func (s *WebAuthnService) SignupVerify(ctx context.Context, req SignupVerifyRequest) (AuthenticatedCredential, error) {
	return s.finishRegistration(ctx, req.RegistrationID, req.Response)
}

func (s *WebAuthnService) finishRegistration(ctx context.Context, registrationID string, response json.RawMessage) (AuthenticatedCredential, error) {
	if strings.TrimSpace(registrationID) == "" || len(response) == 0 {
		return AuthenticatedCredential{}, ErrRejected
	}
	ceremony, err := s.takeRegistration(registrationID)
	if err != nil {
		return AuthenticatedCredential{}, err
	}
	user := javaUser{account: ceremony.Account}
	credential, err := s.webAuthn.FinishRegistration(user, ceremony.Session, rawCredentialRequest(response))
	if err != nil {
		return AuthenticatedCredential{}, err
	}
	record := javawire.Credential{
		Label:             ceremony.Label,
		Active:            true,
		CredentialID:      javawire.EncodeBase64URL(credential.ID),
		PublicKeyCOSE:     javawire.EncodeBase64URL(credential.PublicKey),
		SignCount:         credential.Authenticator.SignCount,
		Transports:        transportStrings(credential.Transport),
		RPID:              s.webAuthn.Config.RPID,
		Origin:            firstOrigin(s.webAuthn.Config.RPOrigins),
		DeviceType:        deviceType(credential.Flags),
		BackupEligible:    credential.Flags.BackupEligible,
		BackedUp:          credential.Flags.BackupState,
		AllowedCharacters: []string{},
	}
	if ceremony.Signup {
		if _, err := s.java.SignupPasskey(ctx, ceremony.Account, ceremony.Label, record); err != nil {
			return AuthenticatedCredential{}, err
		}
	} else if _, err := s.java.RegisterPasskey(ctx, ceremony.Account, ceremony.Label, record); err != nil {
		return AuthenticatedCredential{}, err
	}
	return AuthenticatedCredential{Account: ceremony.Account, CredentialID: record.CredentialID, CredentialLabel: ceremony.Label}, nil
}

func (s *WebAuthnService) takeLogin(id string) (loginCeremony, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ceremony, ok := s.loginPending[id]
	delete(s.loginPending, id)
	if !ok || !s.now().Before(ceremony.ExpiresAt) {
		return loginCeremony{}, ErrNotFound
	}
	return ceremony, nil
}

func (s *WebAuthnService) takeRegistration(id string) (registrationCeremony, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ceremony, ok := s.regPending[id]
	delete(s.regPending, id)
	if !ok || !s.now().Before(ceremony.ExpiresAt) {
		return registrationCeremony{}, ErrNotFound
	}
	return ceremony, nil
}

func (s *WebAuthnService) pruneLocked() {
	now := s.now()
	if !s.nextPruneTime.IsZero() && now.Before(s.nextPruneTime) {
		return
	}
	for id, ceremony := range s.loginPending {
		if !now.Before(ceremony.ExpiresAt) {
			delete(s.loginPending, id)
		}
	}
	for id, ceremony := range s.regPending {
		if !now.Before(ceremony.ExpiresAt) {
			delete(s.regPending, id)
		}
	}
	s.nextPruneTime = now.Add(s.ttl)
}

type javaUser struct {
	account     string
	credentials []javawire.Credential
}

func (u javaUser) WebAuthnID() []byte          { return []byte(u.account) }
func (u javaUser) WebAuthnName() string        { return u.account }
func (u javaUser) WebAuthnDisplayName() string { return u.account }
func (u javaUser) WebAuthnCredentials() []webauthnlib.Credential {
	credentials := make([]webauthnlib.Credential, 0, len(u.credentials))
	for _, record := range u.credentials {
		id, err := javawire.DecodeBase64URL(record.CredentialID)
		if err != nil {
			continue
		}
		publicKey, err := javawire.DecodeBase64URL(record.PublicKeyCOSE)
		if err != nil {
			continue
		}
		credentials = append(credentials, webauthnlib.Credential{
			ID:        id,
			PublicKey: publicKey,
			Transport: func() []protocol.AuthenticatorTransport {
				out := make([]protocol.AuthenticatorTransport, 0, len(record.Transports))
				for _, transport := range record.Transports {
					if cleaned := strings.TrimSpace(transport); cleaned != "" {
						out = append(out, protocol.AuthenticatorTransport(cleaned))
					}
				}
				return out
			}(),
			Authenticator: webauthnlib.Authenticator{
				SignCount: record.SignCount,
			},
			Flags: webauthnlib.CredentialFlags{
				BackupEligible: credentialBackupEligible(record),
				BackupState:    record.BackedUp,
			},
		})
	}
	return credentials
}

func credentialBackupEligible(record javawire.Credential) bool {
	if record.BackupEligible || record.BackedUp {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(record.DeviceType), "multiDevice")
}

func rawCredentialRequest(raw json.RawMessage) *http.Request {
	return &http.Request{
		Body:   ioReadCloser{Reader: bytes.NewReader(raw)},
		Header: http.Header{"Content-Type": []string{"application/json"}},
	}
}

type ioReadCloser struct {
	*bytes.Reader
}

func (c ioReadCloser) Close() error { return nil }

func (s *WebAuthnService) registrationAccount(ctx context.Context, pairingToken string) (string, error) {
	token := strings.TrimSpace(pairingToken)
	if token == "" {
		return "", ErrRejected
	}
	if s.allowLocalAccountPairing && strings.HasPrefix(token, "account:") {
		account := strings.TrimSpace(strings.TrimPrefix(token, "account:"))
		if account == "" {
			return "", ErrRejected
		}
		return account, nil
	}
	claim, err := s.java.ClaimPairing(ctx, token)
	if err != nil {
		return "", err
	}
	account := strings.TrimSpace(claim.Account)
	if account == "" {
		return "", ErrRejected
	}
	return account, nil
}

func labelForCredential(credentials []javawire.Credential, credentialID string) string {
	for _, credential := range credentials {
		if credential.CredentialID == credentialID {
			if credential.Label != "" {
				return credential.Label
			}
			return "passkey"
		}
	}
	return "passkey"
}

func transportStrings(transports []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(transports))
	for _, transport := range transports {
		if transport != "" {
			out = append(out, string(transport))
		}
	}
	return out
}

func deviceType(flags webauthnlib.CredentialFlags) string {
	if flags.BackupEligible {
		return "multiDevice"
	}
	return "singleDevice"
}

func firstOrigin(origins []string) string {
	if len(origins) == 0 {
		return ""
	}
	return origins[0]
}

func randomID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return javawire.EncodeBase64URL(raw), nil
}

func normalizeSignupAccount(value string) (string, error) {
	account := strings.TrimSpace(value)
	if len(account) < 3 || len(account) > 32 || isReservedSignupAccount(account) {
		return "", ErrRejected
	}
	if !isSafeAccountName(account) {
		return "", ErrRejected
	}
	return account, nil
}

func normalizeLoginAccount(value string) (string, error) {
	account := strings.TrimSpace(value)
	if len(account) < 3 || len(account) > 32 {
		return "", ErrRejected
	}
	if !isSafeAccountName(account) {
		return "", ErrRejected
	}
	return account, nil
}

func isSafeAccountName(account string) bool {
	for _, ch := range account {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' {
			continue
		}
		return false
	}
	return true
}

func normalizePasskeyLabel(value string) (string, error) {
	label := strings.TrimSpace(value)
	if len(label) < 1 || len(label) > 48 {
		return "", ErrRejected
	}
	for _, ch := range label {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' {
			continue
		}
		return "", ErrRejected
	}
	return label, nil
}

func isReservedSignupAccount(account string) bool {
	normalized := strings.ToLower(strings.TrimSpace(account))
	return normalized == "matt" ||
		normalized == "root" ||
		normalized == "admin" ||
		normalized == "sysop" ||
		strings.HasPrefix(normalized, "ai_pool_")
}
