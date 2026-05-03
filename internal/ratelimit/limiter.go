package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	now     func() time.Time
	buckets map[string]bucket
}

type bucket struct {
	start time.Time
	used  int
}

func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:   limit,
		window:  window,
		now:     time.Now,
		buckets: make(map[string]bucket),
	}
}

func (l *Limiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[key]
	if b.start.IsZero() || now.Sub(b.start) >= l.window {
		l.buckets[key] = bucket{start: now, used: 1}
		return true
	}
	if b.used >= l.limit {
		return false
	}
	b.used++
	l.buckets[key] = b
	return true
}
