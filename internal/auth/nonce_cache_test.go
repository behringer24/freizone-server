package auth

import (
	"testing"
	"time"
)

func TestNonceCacheRecordDetectsReplay(t *testing.T) {
	c := newNonceCache()
	now := time.Now()
	exp := now.Add(MaxClockSkew)

	if ok := c.record("dev1", "nonceA", now, exp); !ok {
		t.Fatal("first record should be accepted (ok=true)")
	}
	if ok := c.record("dev1", "nonceA", now, exp); ok {
		t.Fatal("immediate replay of the same (device, nonce) should be rejected (ok=false)")
	}
}

func TestNonceCacheScopedByDevice(t *testing.T) {
	c := newNonceCache()
	now := time.Now()
	exp := now.Add(MaxClockSkew)

	if ok := c.record("dev1", "shared", now, exp); !ok {
		t.Fatal("dev1 first use should be accepted")
	}
	// Same nonce string, different device -> not a replay.
	if ok := c.record("dev2", "shared", now, exp); !ok {
		t.Fatal("same nonce under a different device must not count as a replay")
	}
}

func TestNonceCacheExpiredEntryIsNotAReplay(t *testing.T) {
	c := newNonceCache()
	t0 := time.Now()
	exp := t0.Add(MaxClockSkew)

	if ok := c.record("dev1", "nonceA", t0, exp); !ok {
		t.Fatal("first record should be accepted")
	}
	// Evaluate "now" past the entry's expiry: the old record is stale, so the
	// same nonce is allowed again (the skew check would already have rejected
	// such an old timestamp upstream).
	later := exp.Add(time.Second)
	if ok := c.record("dev1", "nonceA", later, later.Add(MaxClockSkew)); !ok {
		t.Fatal("a re-use after the prior record expired must be accepted")
	}
}

func TestNonceCachePurgeExpired(t *testing.T) {
	c := newNonceCache()
	t0 := time.Now()

	c.record("dev1", "old", t0, t0.Add(1*time.Minute))
	c.record("dev1", "fresh", t0, t0.Add(10*time.Minute))

	// Five minutes on, only "old" has expired.
	removed := c.purgeExpired(t0.Add(5 * time.Minute))
	if removed != 1 {
		t.Fatalf("purgeExpired removed %d, want 1", removed)
	}
	// "fresh" is still remembered -> re-use is still a replay.
	if ok := c.record("dev1", "fresh", t0.Add(5*time.Minute), t0.Add(15*time.Minute)); ok {
		t.Fatal("the still-valid nonce should remain a replay after purge")
	}
	// "old" was purged -> no longer a replay.
	if ok := c.record("dev1", "old", t0.Add(5*time.Minute), t0.Add(15*time.Minute)); !ok {
		t.Fatal("the purged nonce should be accepted again")
	}
}
