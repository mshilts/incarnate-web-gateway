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
	ErrNotFound = errors.New("passkey ceremony not found")
	ErrRejected = errors.New("passkey ceremony rejected")
)

type JavaClient interface {
	ClaimPairing(context.Context, string) (javawire.PairingClaimResult, error)
	LookupPasskeys(context.Context, string) (javawire.LookupResult, error)
	RegisterPasskey(context.Context, string, string, javawire.Credential) (javawire.RegisterResult, error)
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
	Account     string
	Credentials []javawire.Credential
	Session     webauthnlib.SessionData
	ExpiresAt   time.Time
}

type registrationCeremony struct {
	Account   string
	Label     string
	Session   webauthnlib.SessionData
	ExpiresAt time.Time
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
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
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

func (s *WebAuthnService) RegistrationOptions(ctx context.Context, req RegistrationOptionsRequest) (map[string]any, error) {
	account, err := s.registrationAccount(ctx, req.PairingToken)
	if err != nil {
		return nil, err
	}
	label := strings.TrimSpace(req.Label)
	if account == "" || label == "" {
		return nil, ErrRejected
	}
	lookup, err := s.java.LookupPasskeys(ctx, account)
	if err != nil {
		return nil, err
	}
	user := javaUser{account: account, credentials: lookup.Credentials}
	creation, session, err := s.webAuthn.BeginRegistration(user,
		webauthnlib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
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
	if strings.TrimSpace(req.RegistrationID) == "" || len(req.Response) == 0 {
		return AuthenticatedCredential{}, ErrRejected
	}
	ceremony, err := s.takeRegistration(req.RegistrationID)
	if err != nil {
		return AuthenticatedCredential{}, err
	}
	user := javaUser{account: ceremony.Account}
	credential, err := s.webAuthn.FinishRegistration(user, ceremony.Session, rawCredentialRequest(req.Response))
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
		BackedUp:          credential.Flags.BackupState,
		AllowedCharacters: []string{},
	}
	if _, err := s.java.RegisterPasskey(ctx, ceremony.Account, ceremony.Label, record); err != nil {
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
		})
	}
	return credentials
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
