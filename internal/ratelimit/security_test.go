package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func TestSecurityRateLimitBlocksBurstByKey(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := New(20, time.Minute)
	limiter.SetClock(func() time.Time { return now })

	for i := 0; i < 20; i++ {
		if !limiter.Allow("login-options:203.0.113.10") {
			t.Fatalf("request %d was limited early", i+1)
		}
	}
	if limiter.Allow("login-options:203.0.113.10") {
		t.Fatal("burst above configured limit was allowed")
	}
}

func TestSecurityRateLimitDoesNotCollapseSeparateKeys(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := New(2, time.Minute)
	limiter.SetClock(func() time.Time { return now })

	for i := 0; i < 2; i++ {
		if !limiter.Allow("login-options:203.0.113.10") {
			t.Fatalf("login-options request %d was limited early", i+1)
		}
	}
	if !limiter.Allow("login-verify:203.0.113.10") {
		t.Fatal("separate action key was collapsed into login-options bucket")
	}
	if !limiter.Allow("login-options:203.0.113.11") {
		t.Fatal("separate client key was collapsed into exhausted client bucket")
	}
}

func TestSecurityRateLimitPrunesHighCardinalityAttackBuckets(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := New(1, time.Minute)
	limiter.SetClock(func() time.Time { return now })

	for i := 0; i < 1000; i++ {
		if !limiter.Allow(fmt.Sprintf("login-options:203.0.113.%d", i)) {
			t.Fatalf("initial request for key %d was limited", i)
		}
	}
	if len(limiter.buckets) != 1000 {
		t.Fatalf("bucket count = %d, want 1000", len(limiter.buckets))
	}

	now = now.Add(time.Minute)
	if !limiter.Allow("login-options:198.51.100.1") {
		t.Fatal("new key was limited after window")
	}
	if len(limiter.buckets) != 1 {
		t.Fatalf("expired high-cardinality buckets were not pruned, count = %d", len(limiter.buckets))
	}
}
