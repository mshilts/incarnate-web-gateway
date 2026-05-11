package session

import (
	"errors"
	"testing"
	"time"
)

func TestSecuritySessionRejectsExpiredRecords(t *testing.T) {
	cases := []struct {
		name    string
		ttl     time.Duration
		idleTTL time.Duration
		advance time.Duration
	}{
		{name: "absolute-ttl", ttl: 10 * time.Minute, idleTTL: time.Hour, advance: 11 * time.Minute},
		{name: "idle-ttl", ttl: time.Hour, idleTTL: 10 * time.Minute, advance: 11 * time.Minute},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			store := NewStore(tc.ttl, tc.idleTTL)
			store.SetClock(func() time.Time { return now })
			record, err := store.Create("matt", "cred", "iphone")
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			now = now.Add(tc.advance)
			if _, err := store.Get(record.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get expired session error = %v, want %v", err, ErrNotFound)
			}
			if _, ok := store.records[record.ID]; ok {
				t.Fatal("expired session remained in store after failed Get")
			}
		})
	}
}

func TestSecuritySessionIdleTTLRequiresActivity(t *testing.T) {
	now := time.Unix(1000, 0)
	store := NewStore(time.Hour, 10*time.Minute)
	store.SetClock(func() time.Time { return now })
	record, err := store.Create("matt", "cred", "iphone")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for i := 0; i < 3; i++ {
		now = now.Add(9 * time.Minute)
		if _, err := store.Get(record.ID); err != nil {
			t.Fatalf("Get active session %d: %v", i+1, err)
		}
	}

	now = now.Add(11 * time.Minute)
	if _, err := store.Get(record.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get idle session error = %v, want %v", err, ErrNotFound)
	}
}

func TestSecuritySessionTouchRefreshesIdleButNotAbsoluteTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	store := NewStore(30*time.Minute, 10*time.Minute)
	store.SetClock(func() time.Time { return now })
	record, err := store.Create("matt", "cred", "iphone")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	now = now.Add(9 * time.Minute)
	if touched, err := store.Touch(record.ID); err != nil {
		t.Fatalf("Touch active session: %v", err)
	} else if !touched.ExpiresAt.Equal(record.ExpiresAt) {
		t.Fatalf("Touch extended absolute expiry: got %v want %v", touched.ExpiresAt, record.ExpiresAt)
	}

	now = now.Add(9 * time.Minute)
	if _, err := store.Get(record.ID); err != nil {
		t.Fatalf("Get session after refreshed idle window: %v", err)
	}

	now = record.ExpiresAt
	if _, err := store.Touch(record.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Touch absolute-expired session error = %v, want %v", err, ErrNotFound)
	}
}
