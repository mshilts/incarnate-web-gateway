package session

import (
	"errors"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	now := time.Unix(1000, 0)
	store := NewStore(time.Hour, 10*time.Minute)
	store.SetClock(func() time.Time { return now })

	record, err := store.Create("matt", "cred", "iphone")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if record.ID == "" {
		t.Fatal("Create returned empty ID")
	}
	got, err := store.Get(record.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Account != "matt" {
		t.Fatalf("Account = %q", got.Account)
	}

	now = now.Add(11 * time.Minute)
	if _, err := store.Get(record.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired idle session error = %v", err)
	}
}

func TestSessionDelete(t *testing.T) {
	store := NewStore(time.Hour, time.Hour)
	record, err := store.Create("matt", "cred", "iphone")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	store.Delete(record.ID)
	if _, err := store.Get(record.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete error = %v", err)
	}
}

func TestSessionCreatePrunesExpiredRecords(t *testing.T) {
	now := time.Unix(1000, 0)
	store := NewStore(time.Hour, 10*time.Minute)
	store.SetClock(func() time.Time { return now })

	oldRecord, err := store.Create("matt", "cred", "iphone")
	if err != nil {
		t.Fatalf("Create old session: %v", err)
	}

	now = now.Add(11 * time.Minute)
	newRecord, err := store.Create("matt", "cred-2", "ipad")
	if err != nil {
		t.Fatalf("Create new session: %v", err)
	}
	if _, ok := store.records[oldRecord.ID]; ok {
		t.Fatal("expired session was not pruned")
	}
	if _, ok := store.records[newRecord.ID]; !ok {
		t.Fatal("new session was not stored")
	}
}
