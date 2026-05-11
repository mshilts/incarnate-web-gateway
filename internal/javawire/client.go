package javawire

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	MaxResponseBytes = 256 * 1024
)

var (
	ErrRejected = errors.New("java gateway command rejected")
	ErrProtocol = errors.New("java gateway protocol violation")
)

type Client struct {
	Addr      string
	Signer    Signer
	Timeout   time.Duration
	MaxLine   int
	Dialer    func(context.Context, string) (net.Conn, error)
	Now       func() time.Time
	NonceFunc func() (string, error)
}

type Credential struct {
	Label             string   `json:"label"`
	Active            bool     `json:"active,omitempty"`
	CredentialID      string   `json:"credentialId"`
	PublicKeyCOSE     string   `json:"publicKeyCose"`
	SignCount         uint32   `json:"signCount"`
	Transports        []string `json:"transports"`
	RPID              string   `json:"rpId"`
	Origin            string   `json:"origin"`
	DeviceType        string   `json:"deviceType,omitempty"`
	BackedUp          bool     `json:"backedUp,omitempty"`
	AllowedCharacters []string `json:"allowedCharacters"`
}

type LookupResult struct {
	Type        string       `json:"type"`
	OK          bool         `json:"ok"`
	Accepted    bool         `json:"accepted,omitempty"`
	Account     string       `json:"account"`
	Credentials []Credential `json:"credentials"`
	Message     string       `json:"message,omitempty"`
}

type RegisterResult struct {
	Type     string `json:"type"`
	OK       bool   `json:"ok"`
	Accepted bool   `json:"accepted,omitempty"`
	Account  string `json:"account"`
	Label    string `json:"label"`
	Message  string `json:"message,omitempty"`
}

type PairingClaimResult struct {
	Type     string `json:"type"`
	OK       bool   `json:"ok"`
	Accepted bool   `json:"accepted,omitempty"`
	Account  string `json:"account"`
	Message  string `json:"message,omitempty"`
}

type SessionResult struct {
	Type            string `json:"type"`
	OK              bool   `json:"ok"`
	Accepted        bool   `json:"accepted,omitempty"`
	Account         string `json:"account"`
	CredentialLabel string `json:"credentialLabel"`
	Message         string `json:"message,omitempty"`
}

type CounterResult struct {
	Type     string `json:"type"`
	OK       bool   `json:"ok"`
	Accepted bool   `json:"accepted,omitempty"`
	Message  string `json:"message,omitempty"`
}

func (c Client) LookupPasskeys(ctx context.Context, account string) (LookupResult, error) {
	var result LookupResult
	if err := c.roundTrip(ctx, map[string]any{
		"type":    "gateway_passkey_lookup",
		"account": account,
	}, "gateway_passkey_lookup_result", &result); err != nil {
		return LookupResult{}, err
	}
	if result.Account != "" && result.Account != account {
		return LookupResult{}, fmt.Errorf("%w: lookup account mismatch", ErrProtocol)
	}
	return result, nil
}

func (c Client) RegisterPasskey(ctx context.Context, account, label string, credential Credential) (RegisterResult, error) {
	var result RegisterResult
	if err := c.roundTrip(ctx, map[string]any{
		"type":       "gateway_passkey_register",
		"account":    account,
		"label":      label,
		"credential": credential,
	}, "gateway_passkey_register_result", &result); err != nil {
		return RegisterResult{}, err
	}
	if result.Account != "" && result.Account != account {
		return RegisterResult{}, fmt.Errorf("%w: register account mismatch", ErrProtocol)
	}
	return result, nil
}

func (c Client) SignupPasskey(ctx context.Context, account, label string, credential Credential) (RegisterResult, error) {
	var result RegisterResult
	if err := c.roundTrip(ctx, map[string]any{
		"type":       "gateway_passkey_signup",
		"account":    account,
		"label":      label,
		"credential": credential,
	}, "gateway_passkey_signup_result", &result); err != nil {
		return RegisterResult{}, err
	}
	if result.Account != "" && result.Account != account {
		return RegisterResult{}, fmt.Errorf("%w: signup account mismatch", ErrProtocol)
	}
	return result, nil
}

func (c Client) ClaimPairing(ctx context.Context, token string) (PairingClaimResult, error) {
	var result PairingClaimResult
	if err := c.roundTrip(ctx, map[string]any{
		"type":         "gateway_pairing_claim",
		"pairingToken": token,
	}, "gateway_pairing_claim_result", &result); err != nil {
		return PairingClaimResult{}, err
	}
	if strings.TrimSpace(result.Account) == "" {
		return PairingClaimResult{}, fmt.Errorf("%w: pairing claim returned empty account", ErrProtocol)
	}
	return result, nil
}

func (c Client) UpdateCounter(ctx context.Context, account, credentialID string, signCount uint32) (CounterResult, error) {
	var result CounterResult
	if err := c.roundTrip(ctx, map[string]any{
		"type":         "gateway_passkey_counter",
		"account":      account,
		"credentialId": credentialID,
		"signCount":    signCount,
	}, "gateway_passkey_counter_result", &result); err != nil {
		return CounterResult{}, err
	}
	return result, nil
}

func (c Client) BeginSession(ctx context.Context, account, credentialID, credentialLabel, sessionID string, expiresAt time.Time) (net.Conn, *bufio.Reader, SessionResult, error) {
	conn, reader, err := c.open(ctx)
	if err != nil {
		return nil, nil, SessionResult{}, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()
	payload := map[string]any{
		"type":             "gateway_session_begin",
		"account":          account,
		"credentialId":     credentialID,
		"credentialLabel":  credentialLabel,
		"gatewaySessionId": sessionID,
		"clientKind":       "browser",
		"expiresAt":        expiresAt.UnixMilli(),
	}
	var result SessionResult
	if err := c.writeSigned(conn, payload); err != nil {
		return nil, nil, SessionResult{}, err
	}
	if err := c.readTyped(reader, "gateway_session_result", &result); err != nil {
		return nil, nil, SessionResult{}, err
	}
	if result.Account != "" && result.Account != account {
		return nil, nil, SessionResult{}, fmt.Errorf("%w: session account mismatch", ErrProtocol)
	}
	_ = conn.SetDeadline(time.Time{})
	closeOnError = false
	return conn, reader, result, nil
}

func (c Client) roundTrip(ctx context.Context, payload map[string]any, expectedType string, dst any) error {
	conn, reader, err := c.open(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := c.writeSigned(conn, payload); err != nil {
		return err
	}
	return c.readTyped(reader, expectedType, dst)
}

func (c Client) open(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := c.Dialer
	if dial == nil {
		var d net.Dialer
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	conn, err := dial(ctx, c.Addr)
	if err != nil {
		return nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	maxLine := c.MaxLine
	if maxLine <= 0 {
		maxLine = MaxResponseBytes
	}
	return conn, bufio.NewReaderSize(conn, maxLine), nil
}

func (c Client) writeSigned(conn net.Conn, payload map[string]any) error {
	signer := c.Signer
	if c.Now != nil {
		signer.Now = c.Now
	}
	signed, err := signer.SignWithNonce(payload, c.NonceFunc)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	_, err = conn.Write(encoded)
	return err
}

func (c Client) readTyped(reader *bufio.Reader, expectedType string, dst any) error {
	maxLine := c.MaxLine
	if maxLine <= 0 {
		maxLine = MaxResponseBytes
	}
	for skipped := 0; skipped < 8; skipped++ {
		line, err := readLineBounded(reader, maxLine)
		if err != nil {
			return err
		}
		var envelope struct {
			Type     string `json:"type"`
			OK       bool   `json:"ok"`
			Accepted bool   `json:"accepted"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			return fmt.Errorf("%w: invalid json response", ErrProtocol)
		}
		if envelope.Type != expectedType {
			if isSkippableStartupFrame(envelope.Type) {
				continue
			}
			return fmt.Errorf("%w: expected %s got %s", ErrProtocol, expectedType, envelope.Type)
		}
		if !envelope.OK && !envelope.Accepted {
			return ErrRejected
		}
		if err := json.Unmarshal(line, dst); err != nil {
			return fmt.Errorf("%w: invalid typed response", ErrProtocol)
		}
		return nil
	}
	return fmt.Errorf("%w: expected %s after startup frames", ErrProtocol, expectedType)
}

func isSkippableStartupFrame(frameType string) bool {
	switch frameType {
	case "hello", "prompt", "session_state":
		return true
	default:
		return false
	}
}

func readLineBounded(reader *bufio.Reader, maxLine int) ([]byte, error) {
	line, isPrefix, err := reader.ReadLine()
	if err != nil {
		return nil, err
	}
	if isPrefix || len(line) > maxLine {
		return nil, fmt.Errorf("%w: response line too large", ErrProtocol)
	}
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return nil, fmt.Errorf("%w: empty response", ErrProtocol)
	}
	return []byte(trimmed), nil
}

func DecodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func EncodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
