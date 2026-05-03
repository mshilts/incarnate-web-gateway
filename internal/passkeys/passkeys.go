package passkeys

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("passkey ceremonies are placeholders in v0.1")

type LoginOptionsRequest struct {
	Account string `json:"account"`
}

type RegistrationOptionsRequest struct {
	PairingToken string `json:"pairingToken"`
	Label        string `json:"label"`
}

type Service interface {
	LoginOptions(context.Context, LoginOptionsRequest) (map[string]any, error)
	LoginVerify(context.Context, map[string]any) error
	RegistrationOptions(context.Context, RegistrationOptionsRequest) (map[string]any, error)
	RegistrationVerify(context.Context, map[string]any) error
}

type PlaceholderService struct{}

func (PlaceholderService) LoginOptions(context.Context, LoginOptionsRequest) (map[string]any, error) {
	return nil, ErrNotImplemented
}

func (PlaceholderService) LoginVerify(context.Context, map[string]any) error {
	return ErrNotImplemented
}

func (PlaceholderService) RegistrationOptions(context.Context, RegistrationOptionsRequest) (map[string]any, error) {
	return nil, ErrNotImplemented
}

func (PlaceholderService) RegistrationVerify(context.Context, map[string]any) error {
	return ErrNotImplemented
}
