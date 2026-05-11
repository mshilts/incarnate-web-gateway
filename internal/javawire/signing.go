package javawire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type Signer struct {
	GatewayID string
	Secret    []byte
	Now       func() time.Time
}

func (s Signer) Sign(payload map[string]any) (map[string]any, error) {
	return s.SignWithNonce(payload, nil)
}

func (s Signer) SignWithNonce(payload map[string]any, nonceFunc func() (string, error)) (map[string]any, error) {
	if s.GatewayID == "" {
		return nil, errors.New("gateway id is required")
	}
	if len(s.Secret) < 32 {
		return nil, errors.New("hmac secret must be at least 32 bytes")
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	signed := cloneMap(payload)
	signed["gatewayId"] = s.GatewayID
	signed["issuedAt"] = now().UnixMilli()
	if _, ok := signed["nonce"]; !ok {
		if nonceFunc == nil {
			nonceFunc = randomNonce
		}
		nonce, err := nonceFunc()
		if err != nil {
			return nil, err
		}
		signed["nonce"] = nonce
	}
	canonical, err := CanonicalPayload(signed)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.Secret)
	mac.Write(canonical)
	signed["signature"] = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signed, nil
}

func Verify(secret []byte, signed map[string]any) (bool, error) {
	if len(secret) < 32 {
		return false, errors.New("hmac secret must be at least 32 bytes")
	}
	signature, ok := signed["signature"].(string)
	if !ok || signature == "" {
		return false, errors.New("signature is required")
	}
	unsigned := cloneMap(signed)
	delete(unsigned, "signature")
	canonical, err := CanonicalPayload(unsigned)
	if err != nil {
		return false, err
	}
	expectedMAC := hmac.New(sha256.New, secret)
	expectedMAC.Write(canonical)
	expected := base64.RawURLEncoding.EncodeToString(expectedMAC.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected)), nil
}

func CanonicalPayload(payload map[string]any) ([]byte, error) {
	canonical := cloneMap(payload)
	delete(canonical, "signature")
	return json.Marshal(canonical)
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func randomNonce() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
