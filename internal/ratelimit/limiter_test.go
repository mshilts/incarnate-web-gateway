package ratelimit

import (
	"testing"
	"time"
)

func TestRateLimitBasics(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := New(2, time.Minute)
	limiter.SetClock(func() time.Time { return now })

	if !limiter.Allow("ip:1") || !limiter.Allow("ip:1") {
		t.Fatal("first two requests should be allowed")
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
