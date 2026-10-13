package limit

import (
	"testing"
	"time"
)

func TestLimiterBlocksAfterLimit(t *testing.T) {
	t.Parallel()
	limiter := New(2, time.Minute)
	now := time.Now()
	first := limiter.allow(now, "10.0.0.1", true)
	second := limiter.allow(now, "10.0.0.1", true)
	if !first || !second {
		t.Fatal("events inside the limit were rejected")
	}
	if limiter.allow(now, "10.0.0.1", true) {
		t.Fatal("event over the limit was allowed")
	}
	if !limiter.allow(now, "10.0.0.2", true) {
		t.Fatal("a different key was limited")
	}
}

func TestLimiterWindowExpires(t *testing.T) {
	t.Parallel()
	limiter := New(1, time.Second)
	start := time.Now()
	if !limiter.allow(start, "10.0.0.1", true) {
		t.Fatal("first event was rejected")
	}
	if limiter.allow(start.Add(time.Second), "10.0.0.1", false) {
		t.Fatal("event was permitted at the window boundary")
	}
	if !limiter.allow(start.Add(time.Second+time.Millisecond), "10.0.0.1", true) {
		t.Fatal("event was rejected after the window expired")
	}
}

func TestDisabledLimiterAllowsEverything(t *testing.T) {
	t.Parallel()
	limiter := New(-1, time.Minute)
	for range 5 {
		if !limiter.Allow("same") {
			t.Fatal("disabled limiter rejected an event")
		}
	}
}
