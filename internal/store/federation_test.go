package store

import (
	"errors"
	"testing"
	"time"
)

func TestIsFederationBlockedDefaultFalse(t *testing.T) {
	db := newTestDB(t)

	blocked, err := IsFederationBlocked(db, "some-account")
	if err != nil {
		t.Fatalf("IsFederationBlocked() error = %v", err)
	}
	if blocked {
		t.Error("blocked = true, want false for an account never blocked")
	}
}

func TestBlockAndUnblockFederationSender(t *testing.T) {
	db := newTestDB(t)
	reason := "spamming"

	if err := BlockFederationSender(db, "acct1", "admin1", &reason, time.Now()); err != nil {
		t.Fatalf("BlockFederationSender() error = %v", err)
	}

	blocked, err := IsFederationBlocked(db, "acct1")
	if err != nil {
		t.Fatalf("IsFederationBlocked() error = %v", err)
	}
	if !blocked {
		t.Error("blocked = false, want true after BlockFederationSender")
	}

	entries, err := ListFederationBlocklist(db)
	if err != nil {
		t.Fatalf("ListFederationBlocklist() error = %v", err)
	}
	if len(entries) != 1 || entries[0].AccountID != "acct1" || entries[0].BlockedBy != "admin1" {
		t.Fatalf("entries = %+v, want one entry for acct1 blocked by admin1", entries)
	}
	if entries[0].Reason == nil || *entries[0].Reason != reason {
		t.Errorf("reason = %v, want %q", entries[0].Reason, reason)
	}

	if err := UnblockFederationSender(db, "acct1"); err != nil {
		t.Fatalf("UnblockFederationSender() error = %v", err)
	}
	blocked, err = IsFederationBlocked(db, "acct1")
	if err != nil {
		t.Fatalf("IsFederationBlocked() error = %v", err)
	}
	if blocked {
		t.Error("blocked = true, want false after UnblockFederationSender")
	}
}

func TestUnblockFederationSenderNotFound(t *testing.T) {
	db := newTestDB(t)

	err := UnblockFederationSender(db, "never-blocked")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestBlockFederationSenderReblockUpdatesReason(t *testing.T) {
	db := newTestDB(t)
	first := "first reason"
	second := "second reason"

	if err := BlockFederationSender(db, "acct1", "admin1", &first, time.Now()); err != nil {
		t.Fatalf("BlockFederationSender() error = %v", err)
	}
	if err := BlockFederationSender(db, "acct1", "admin2", &second, time.Now()); err != nil {
		t.Fatalf("BlockFederationSender() (re-block) error = %v", err)
	}

	entries, err := ListFederationBlocklist(db)
	if err != nil {
		t.Fatalf("ListFederationBlocklist() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %+v, want exactly one (re-blocking is an upsert, not a duplicate)", entries)
	}
	if entries[0].BlockedBy != "admin2" || entries[0].Reason == nil || *entries[0].Reason != second {
		t.Errorf("entries[0] = %+v, want blocked_by=admin2 reason=%q (latest block wins)", entries[0], second)
	}
}
