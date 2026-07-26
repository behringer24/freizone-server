package auth

import (
	"hash/fnv"
	"sync"
	"time"
)

// nonceShards is the number of independently-locked partitions the nonce
// cache is split across. Nonce recording happens on every single signed
// request -- the hottest write path -- so sharding keeps that off one global
// lock. A power of two so the mask below distributes cheaply.
const nonceShards = 256

// nonceCache is an in-memory replay guard: it remembers (deviceID, nonce)
// pairs until their signature-skew window expires, so a captured request
// can't be replayed within that window. It deliberately does NOT persist:
// nonces are purely ephemeral (5-minute TTL) and losing them on restart only
// briefly reopens a narrow, hard-to-exploit replay window (see the middleware
// / plan notes), which is worth trading for taking this write off SQLite.
type nonceCache struct {
	shards [nonceShards]nonceShard
}

type nonceShard struct {
	mu   sync.Mutex
	seen map[string]time.Time // key -> expiry
}

func newNonceCache() *nonceCache {
	c := &nonceCache{}
	for i := range c.shards {
		c.shards[i].seen = make(map[string]time.Time)
	}
	return c
}

func (c *nonceCache) shardFor(deviceID string) *nonceShard {
	h := fnv.New32a()
	h.Write([]byte(deviceID))
	return &c.shards[h.Sum32()&(nonceShards-1)]
}

func nonceKey(deviceID, nonce string) string {
	return deviceID + "\x00" + nonce
}

// Record marks (deviceID, nonce) as used until expiresAt. It returns ok=true
// the first time the pair is seen and ok=false if an unexpired record already
// exists (a replay). An existing but already-expired record does not count as
// a replay -- the caller's timestamp-skew check would have rejected such an
// old request anyway -- and is overwritten. The now argument is passed in so
// tests can control time.
func (c *nonceCache) record(deviceID, nonce string, now, expiresAt time.Time) (ok bool) {
	key := nonceKey(deviceID, nonce)
	s := c.shardFor(deviceID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, exists := s.seen[key]; exists && exp.After(now) {
		return false
	}
	s.seen[key] = expiresAt
	return true
}

// purgeExpired removes all records whose expiry is at or before now, across
// all shards, returning the number removed. Called periodically by the
// server's cleanup ticker to keep the maps bounded when traffic is idle.
func (c *nonceCache) purgeExpired(now time.Time) int {
	removed := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for k, exp := range s.seen {
			if !exp.After(now) {
				delete(s.seen, k)
				removed++
			}
		}
		s.mu.Unlock()
	}
	return removed
}
