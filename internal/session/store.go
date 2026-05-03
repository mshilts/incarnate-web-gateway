package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("session not found")

type Record struct {
	ID            string
	Account       string
	CredentialID  string
	CredentialLbl string
	CreatedAt     time.Time
	LastSeenAt    time.Time
	ExpiresAt     time.Time
}

type Store struct {
	mu        sync.Mutex
	ttl       time.Duration
	idleTTL   time.Duration
	now       func() time.Time
	nextPrune time.Time
	records   map[string]Record
}

func NewStore(ttl, idleTTL time.Duration) *Store {
	return &Store{
		ttl:     ttl,
		idleTTL: idleTTL,
		now:     time.Now,
		records: make(map[string]Record),
	}
}

func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

func (s *Store) Create(account, credentialID, credentialLabel string) (Record, error) {
	id, err := randomID()
	if err != nil {
		return Record{}, err
	}
	now := s.now()
	record := Record{
		ID:            id,
		Account:       account,
		CredentialID:  credentialID,
		CredentialLbl: credentialLabel,
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(s.ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(now)
	s.records[id] = record
	return record, nil
}

func (s *Store) Get(id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	now := s.now()
	if s.expired(record, now) {
		delete(s.records, id)
		return Record{}, ErrNotFound
	}
	record.LastSeenAt = now
	s.records[id] = record
	return record, nil
}

func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, id)
}

func (s *Store) pruneExpiredLocked(now time.Time) {
	if len(s.records) == 0 || (!s.nextPrune.IsZero() && now.Before(s.nextPrune)) {
		return
	}
	for id, record := range s.records {
		if s.expired(record, now) {
			delete(s.records, id)
		}
	}
	s.nextPrune = now.Add(minDuration(s.ttl, s.idleTTL))
}

func (s *Store) expired(record Record, now time.Time) bool {
	return !now.Before(record.ExpiresAt) || now.Sub(record.LastSeenAt) > s.idleTTL
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func randomID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
