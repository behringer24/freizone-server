// Package ratchet implements the client-side cryptographic core of
// Freizone's end-to-end encryption: X3DH session establishment and the
// Double Ratchet algorithm, per the specifications at
// https://www.signal.org/docs/specifications/x3dh/ and
// https://www.signal.org/docs/specifications/doubleratchet/. The server
// never sees any of this -- it only relays opaque ciphertext.
package ratchet

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"golang.org/x/crypto/hkdf"
)

const (
	rootKDFInfo = "Freizone-DR-RK-v1"

	// maxSkippedMessageKeys bounds how many out-of-order message keys a
	// single skip run (one chain, one Decrypt call) will buffer, per the
	// Double Ratchet spec's guidance against unbounded memory growth from a
	// malicious or buggy peer.
	maxSkippedMessageKeys = 1000

	// maxTotalSkippedMessageKeys bounds the AGGREGATE size of s.Skipped across
	// the whole session (security audit M3). maxSkippedMessageKeys alone only
	// caps a single run: gaps that are never filled stay buffered forever, and
	// every DH-ratchet step (Nr resets to 0) opens a fresh per-run budget, so
	// an authenticated peer that keeps leaving unfilled gaps -- or just a lossy
	// long-lived session -- could grow the map without bound. When a new run
	// would push past this ceiling, the oldest buffered keys are evicted to
	// make room (never rejected: eviction preserves out-of-order delivery for
	// recent gaps, at the cost of the oldest never-arrived ones). Set to twice
	// the per-run cap so a single Decrypt that legitimately skips a full chain
	// on both the PN and the N step still fits without evicting its own keys.
	maxTotalSkippedMessageKeys = 2 * maxSkippedMessageKeys
)

// Header accompanies every ratchet-encrypted message and is itself part of
// the AEAD associated data (see aead.go).
type Header struct {
	DHPub []byte `json:"dh_pub"` // sender's current ratchet public key, 32 bytes
	PN    uint32 `json:"pn"`     // length of the sender's previous sending chain
	N     uint32 `json:"n"`      // message number within the sender's current sending chain
}

// Bytes returns Header's fixed-width binary encoding.
func (h Header) Bytes() []byte {
	buf := make([]byte, 0, len(h.DHPub)+8)
	buf = append(buf, h.DHPub...)
	var pn, n [4]byte
	binary.BigEndian.PutUint32(pn[:], h.PN)
	binary.BigEndian.PutUint32(n[:], h.N)
	buf = append(buf, pn[:]...)
	buf = append(buf, n[:]...)
	return buf
}

// kdfRK is KDF_RK from the Double Ratchet spec: HKDF-SHA256 with the
// current root key as salt and the new DH output as input key material.
func kdfRK(rk, dhOut []byte) (newRK, newCK []byte, err error) {
	r := hkdf.New(sha256.New, dhOut, rk, []byte(rootKDFInfo))
	out := make([]byte, 64)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, nil, fmt.Errorf("ratchet: deriving root key: %w", err)
	}
	return out[:32], out[32:], nil
}

// kdfCK is KDF_CK from the Double Ratchet spec: HMAC-SHA256 over the
// current chain key, with fixed constants distinguishing the message key
// from the next chain key.
func kdfCK(ck []byte) (newCK, mk []byte) {
	mkMAC := hmac.New(sha256.New, ck)
	mkMAC.Write([]byte{0x01})
	mk = mkMAC.Sum(nil)

	ckMAC := hmac.New(sha256.New, ck)
	ckMAC.Write([]byte{0x02})
	newCK = ckMAC.Sum(nil)

	return newCK, mk
}

// dhRatchetStep performs a full DH ratchet transition on receipt of a
// message whose header carries a new remote ratchet public key: it derives
// the new receiving chain from the existing DHs/remote-pub pair, then
// generates a fresh local ratchet keypair and derives a new sending chain
// from it -- exactly the two-KDF_RK-calls-per-transition structure from the
// spec.
func (s *Session) dhRatchetStep(remoteDHPub []byte) error {
	remotePub, err := ecdh.X25519().NewPublicKey(remoteDHPub)
	if err != nil {
		return fmt.Errorf("ratchet: invalid remote ratchet public key: %w", err)
	}

	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0
	s.DHr = remotePub

	dh, err := s.DHs.ECDH(s.DHr)
	if err != nil {
		return fmt.Errorf("ratchet: dh ratchet (receiving side): %w", err)
	}
	rk, ckr, err := kdfRK(s.RK, dh)
	if err != nil {
		return err
	}
	s.RK, s.CKr = rk, ckr

	newDHs, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ratchet: generating new ratchet key: %w", err)
	}
	s.DHs = newDHs

	dh2, err := s.DHs.ECDH(s.DHr)
	if err != nil {
		return fmt.Errorf("ratchet: dh ratchet (sending side): %w", err)
	}
	rk2, cks, err := kdfRK(s.RK, dh2)
	if err != nil {
		return err
	}
	s.RK, s.CKs = rk2, cks

	return nil
}

// skippedKey identifies a buffered out-of-order message key.
type skippedKey struct {
	dhPub string // s.DHr.Bytes() at the time, as a map-friendly string
	n     uint32
}

// skippedValue is a buffered message key plus a monotonic insertion sequence,
// so the aggregate cap (maxTotalSkippedMessageKeys) can evict the oldest keys
// first. The sequence is persisted, so eviction order survives a reload.
type skippedValue struct {
	mk  []byte
	seq uint64
}

// skipMessageKeys derives and buffers message keys for every message
// number up to (but not including) until in the current receiving chain,
// for out-of-order delivery. A single run is bounded by maxSkippedMessageKeys;
// the buffer as a whole is bounded by maxTotalSkippedMessageKeys, evicting the
// oldest keys to stay under it.
func (s *Session) skipMessageKeys(until uint32) error {
	if until <= s.Nr {
		return nil
	}
	if until-s.Nr > maxSkippedMessageKeys {
		return ErrTooManySkipped
	}
	if s.CKr == nil {
		return ErrNoReceivingChain
	}

	dhKey := ""
	if s.DHr != nil {
		dhKey = string(s.DHr.Bytes())
	}

	if s.Skipped == nil {
		s.Skipped = make(map[skippedKey]skippedValue)
	}
	// Make room for this run up front (never rejects -- see the cap's comment).
	if over := len(s.Skipped) + int(until-s.Nr) - maxTotalSkippedMessageKeys; over > 0 {
		s.evictOldestSkipped(over)
	}

	for s.Nr < until {
		ck, mk := kdfCK(s.CKr)
		s.CKr = ck
		s.Skipped[skippedKey{dhPub: dhKey, n: s.Nr}] = skippedValue{mk: mk, seq: s.skipSeq}
		s.skipSeq++
		s.Nr++
	}
	return nil
}

// evictOldestSkipped removes the n buffered keys with the lowest insertion
// sequence, bounding s.Skipped's memory. n is small (at most one run's worth),
// and only ever called when the aggregate cap would otherwise be exceeded.
func (s *Session) evictOldestSkipped(n int) {
	if n <= 0 || len(s.Skipped) == 0 {
		return
	}
	type ordered struct {
		key skippedKey
		seq uint64
	}
	all := make([]ordered, 0, len(s.Skipped))
	for k, v := range s.Skipped {
		all = append(all, ordered{key: k, seq: v.seq})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seq < all[j].seq })
	if n > len(all) {
		n = len(all)
	}
	for i := 0; i < n; i++ {
		delete(s.Skipped, all[i].key)
	}
}

// trySkippedMessageKey looks up (and consumes) a previously-buffered
// message key for header, if one exists.
func (s *Session) trySkippedMessageKey(header Header) ([]byte, bool) {
	if s.Skipped == nil {
		return nil, false
	}
	key := skippedKey{dhPub: string(header.DHPub), n: header.N}
	v, ok := s.Skipped[key]
	if ok {
		delete(s.Skipped, key)
	}
	return v.mk, ok
}

func headerMatchesDHr(header Header, dhr *ecdh.PublicKey) bool {
	if dhr == nil {
		return false
	}
	return bytes.Equal(header.DHPub, dhr.Bytes())
}
