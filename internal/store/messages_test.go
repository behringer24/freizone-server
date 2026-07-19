package store

import (
	"errors"
	"testing"
	"time"
)

func testMessage(id, recipientDeviceID string) Message {
	now := time.Now()
	return Message{
		MessageID:          id,
		SenderAccountID:    "sender-acct",
		SenderDeviceID:     "sender-device",
		RecipientAccountID: "recipient-acct",
		RecipientDeviceID:  recipientDeviceID,
		Payload:            `{"ciphertext":"abc"}`,
		SentAt:             now,
		ExpiresAt:          now.Add(14 * 24 * time.Hour),
	}
}

func TestCreateAndListPendingMessages(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	if err := CreateMessage(db, testMessage("msg1", "device1")); err != nil {
		t.Fatalf("CreateMessage() error = %v", err)
	}
	if err := CreateMessage(db, testMessage("msg2", "device1")); err != nil {
		t.Fatalf("CreateMessage() error = %v", err)
	}

	messages, err := ListPendingMessages(db, "device1")
	if err != nil {
		t.Fatalf("ListPendingMessages() error = %v", err)
	}
	if len(messages) != 2 {
		t.Fatalf("len(messages) = %d, want 2", len(messages))
	}
	if messages[0].MessageID != "msg1" || messages[1].MessageID != "msg2" {
		t.Errorf("unexpected order: %+v", messages)
	}
}

func TestCountPendingMessages(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	count, err := CountPendingMessages(db, "device1")
	if err != nil {
		t.Fatalf("CountPendingMessages() error = %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0 for a device with nothing queued", count)
	}

	if err := CreateMessage(db, testMessage("msg1", "device1")); err != nil {
		t.Fatalf("CreateMessage() error = %v", err)
	}
	if err := CreateMessage(db, testMessage("msg2", "device1")); err != nil {
		t.Fatalf("CreateMessage() error = %v", err)
	}

	count, err = CountPendingMessages(db, "device1")
	if err != nil {
		t.Fatalf("CountPendingMessages() error = %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}

	// A different device's queue is unaffected.
	count, err = CountPendingMessages(db, "some-other-device")
	if err != nil {
		t.Fatalf("CountPendingMessages() error = %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0 for an unrelated device", count)
	}
}

func TestCreateMessageRejectsDuplicateID(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	if err := CreateMessage(db, testMessage("msg1", "device1")); err != nil {
		t.Fatalf("first CreateMessage() error = %v", err)
	}
	if err := CreateMessage(db, testMessage("msg1", "device1")); !errors.Is(err, ErrConflict) {
		t.Errorf("second CreateMessage() error = %v, want ErrConflict", err)
	}
}

func TestDeleteMessage(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := CreateMessage(db, testMessage("msg1", "device1")); err != nil {
		t.Fatalf("CreateMessage() error = %v", err)
	}

	if err := DeleteMessage(db, "msg1", "device1"); err != nil {
		t.Fatalf("DeleteMessage() error = %v", err)
	}

	messages, err := ListPendingMessages(db, "device1")
	if err != nil {
		t.Fatalf("ListPendingMessages() error = %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("len(messages) = %d, want 0 after delete", len(messages))
	}
}

func TestDeleteMessageNotFoundOrWrongOwner(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := CreateDevice(db, testDevice("acct1", "device2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := CreateMessage(db, testMessage("msg1", "device1")); err != nil {
		t.Fatalf("CreateMessage() error = %v", err)
	}

	if err := DeleteMessage(db, "does-not-exist", "device1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteMessage(unknown id) error = %v, want ErrNotFound", err)
	}
	if err := DeleteMessage(db, "msg1", "device2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteMessage(wrong owner) error = %v, want ErrNotFound", err)
	}
}

func TestPurgeExpiredMessages(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	now := time.Now()
	expired := testMessage("expired", "device1")
	expired.ExpiresAt = now.Add(-time.Hour)
	fresh := testMessage("fresh", "device1")
	fresh.ExpiresAt = now.Add(time.Hour)

	if err := CreateMessage(db, expired); err != nil {
		t.Fatalf("CreateMessage(expired) error = %v", err)
	}
	if err := CreateMessage(db, fresh); err != nil {
		t.Fatalf("CreateMessage(fresh) error = %v", err)
	}

	purged, err := PurgeExpiredMessages(db, now)
	if err != nil {
		t.Fatalf("PurgeExpiredMessages() error = %v", err)
	}
	if purged != 1 {
		t.Errorf("purged = %d, want 1", purged)
	}

	messages, err := ListPendingMessages(db, "device1")
	if err != nil {
		t.Fatalf("ListPendingMessages() error = %v", err)
	}
	if len(messages) != 1 || messages[0].MessageID != "fresh" {
		t.Errorf("remaining messages = %+v, want only 'fresh'", messages)
	}
}
