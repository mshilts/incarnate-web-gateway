package ratelimit

import (
	"testing"
	"time"
)

func TestRateLimitBasics(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := New(2, time.Minute)
	limiter.SetClock(func() time.Time { return now })

	if !limiter.Allow("ip:1") {
		t.Fatal("first request should be allowed")
	}
	if !limiter.Allow("ip:1") {
		t.Fatal("second request should be allowed")
	}
	if limiter.Allow("ip:1") {
		t.Fatal("third request should be limited")
	}
	if !limiter.Allow("ip:2") {
		t.Fatal("separate key should have separate bucket")
	}
	now = now.Add(time.Minute)
	if !limiter.Allow("ip:1") {
		t.Fatal("bucket should reset after window")
	}
}

func TestRateLimitPrunesExpiredBuckets(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := New(1, time.Minute)
	limiter.SetClock(func() time.Time { return now })

	if !limiter.Allow("ip:1") || !limiter.Allow("ip:2") {
		t.Fatal("initial requests should be allowed")
	}
	if len(limiter.buckets) != 2 {
		t.Fatalf("bucket count = %d", len(limiter.buckets))
	}

	now = now.Add(time.Minute)
	if !limiter.Allow("ip:3") {
		t.Fatal("new key should be allowed after window")
	}
	if len(limiter.buckets) != 1 {
		t.Fatalf("expired buckets were not pruned, count = %d", len(limiter.buckets))
	}
}
