package client

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Attachments, end to end. The property that matters most is the one nobody
// can see from outside -- that what reaches the server is not what the user
// chose -- so the stub keeps the uploaded bytes and the tests look at them.

func imageBytes() []byte {
	// Compressible and repetitive on purpose: if any of this survived to the
	// server in the clear, it would be obvious rather than merely different.
	return bytes.Repeat([]byte("a picture of a cat, roughly speaking. "), 64)
}

// A picture travels: uploaded encrypted, described in the message, previewed
// on arrival, downloaded on demand.
func TestAPictureTravelsEncryptedAndArrivesWhole(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	aliceID := identityOf(t, alice).AccountID
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}

	original := imageBytes()
	sent, err := alice.SendText(t.Context(), bobID, "look at this", SendOptions{
		Media: &OutgoingMedia{
			Bytes: original, MimeType: "image/jpeg",
			Width: 800, Height: 600, Thumb: []byte("tiny"),
		},
	})
	if err != nil {
		t.Fatalf("SendText: %v", err)
	}
	if len(sent.Message.Attachments) != 1 || sent.Message.Attachments[0].BlobID == "" {
		t.Fatalf("the sent line must name an uploaded blob, got %+v", sent.Message.Attachments)
	}

	// The property the whole design turns on: the server holds ciphertext.
	stored := srv.blobBytes(sent.Message.Attachments[0].BlobID)
	if len(stored) == 0 {
		t.Fatal("nothing was uploaded")
	}
	if bytes.Contains(stored, []byte("a picture of a cat")) {
		t.Fatal("the plaintext reached the server -- the blob is not encrypted")
	}
	// And it is granted only to the device it was meant for.
	if got := srv.blobRecipientsFor(sent.Message.Attachments[0].BlobID); len(got) != 1 || got[0] != srv.deviceIDs["bob"] {
		t.Errorf("blob recipients: want bob's device alone, got %v", got)
	}

	// The sender keeps its own copy, written before anything could fail.
	own, err := alice.AttachmentFile(bobID, sent.Message.ID)
	if err != nil || !bytes.Equal(own, original) {
		t.Fatalf("the sender's own copy is missing or wrong (%d bytes, %v)", len(own), err)
	}

	got := deliverTo(t, bob)
	if len(got) != 1 {
		t.Fatalf("bob received %d envelopes", len(got))
	}
	if len(got[0].Content.Attachments) != 1 {
		t.Fatalf("the attachment did not survive the envelope: %+v", got[0].Content)
	}
	att := got[0].Content.Attachments[0]
	if att.MimeType != "image/jpeg" || att.Width != 800 || att.Height != 600 {
		t.Errorf("attachment metadata: %+v", att)
	}

	// The preview is on disk already -- written on arrival, without a download.
	thumb, err := bob.AttachmentThumb(aliceID, got[0].StoredMessageID)
	if err != nil || string(thumb) != "tiny" {
		t.Errorf("thumbnail: want %q on disk immediately, got %q (%v)", "tiny", thumb, err)
	}
	if file, _ := bob.AttachmentFile(aliceID, got[0].StoredMessageID); file != nil {
		t.Error("the blob itself must not be downloaded on arrival -- a wake has to notify, not fetch")
	}

	// And the real thing, on demand.
	fetched, err := bob.EnsureAttachment(t.Context(), aliceID, got[0].StoredMessageID, "", att)
	if err != nil {
		t.Fatalf("EnsureAttachment: %v", err)
	}
	if !bytes.Equal(fetched, original) {
		t.Fatalf("the picture came back different: %d bytes vs %d", len(fetched), len(original))
	}

	// Asking again is free: it finds the file rather than downloading twice --
	// which it has to, because the fetch above already released the claim and
	// there is nothing on the server left to ask for (see
	// TestFetchingAnAttachmentReleasesItsClaim).
	again, err := bob.EnsureAttachment(t.Context(), aliceID, got[0].StoredMessageID, "", att)
	if err != nil {
		t.Fatalf("a cached attachment must not need the server: %v", err)
	}
	if !bytes.Equal(again, original) {
		t.Error("the cached copy differs from what was downloaded")
	}
}

// sendPictureTo delivers one picture from alice to bob and returns what bob
// needs to fetch it: the attachment, its stored message id, and alice's id.
func sendPictureTo(t *testing.T, srv *fakeServer, alice, bob *Client) (Attachment, string, string) {
	t.Helper()
	aliceID := identityOf(t, alice).AccountID
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	if _, err := alice.SendText(t.Context(), bobID, "look at this", SendOptions{
		Media: &OutgoingMedia{Bytes: imageBytes(), MimeType: "image/jpeg", Thumb: []byte("tiny")},
	}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	got := deliverTo(t, bob)
	if len(got) != 1 || len(got[0].Content.Attachments) != 1 {
		t.Fatalf("bob did not receive the picture: %+v", got)
	}
	return got[0].Content.Attachments[0], got[0].StoredMessageID, aliceID
}

// The contract from docs/PROTOCOL.md §10: a recipient gives up its claim once
// the plaintext is on disk, so storage is freed on delivery rather than held
// for the whole retention window. This is what regressed silently when the app
// moved its downloads into this package -- the release lived in the Dart path
// that stopped being called, and nothing here noticed.
func TestFetchingAnAttachmentReleasesItsClaim(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	att, messageID, aliceID := sendPictureTo(t, srv, alice, bob)

	if got := srv.blobRecipientsFor(att.BlobID); len(got) != 1 {
		t.Fatalf("before fetching, the blob is claimed by bob's device alone, got %v", got)
	}

	if _, err := bob.EnsureAttachment(t.Context(), aliceID, messageID, "", att); err != nil {
		t.Fatalf("EnsureAttachment: %v", err)
	}

	if got := srv.blobRecipientsFor(att.BlobID); len(got) != 0 {
		t.Errorf("the claim must be given up once the plaintext is stored, still held by %v", got)
	}
	if got := srv.blobCount(); got != 0 {
		t.Errorf("bob was the only recipient, so the ciphertext should be gone, got %d blobs", got)
	}
	// The local copy is what the release traded the server copy for.
	file, err := bob.AttachmentFile(aliceID, messageID)
	if err != nil || !bytes.Equal(file, imageBytes()) {
		t.Fatalf("the local copy must survive the release (%d bytes, %v)", len(file), err)
	}
}

// DeleteBlob has to survive the answer it actually gets. The route is the only
// one in the server that replies 204 with an empty body, and decodeResponse
// reads a bodyless reply as "this host is not a Freizone server" -- so without
// the no-content path this reported failure on every successful release. Worth
// its own test because EnsureAttachment discards the error: every other test
// here would pass with this broken.
func TestDeleteBlobAcceptsAnEmptyResponse(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	att, _, _ := sendPictureTo(t, srv, alice, bob)

	if err := bob.DeleteBlob(t.Context(), att.BlobID); err != nil {
		t.Fatalf("a 204 with no body is success, got %v", err)
	}
	// And again: nothing of ours left to drop is the state being asked for, so
	// the 404 that follows is success too (same rule as AckMessage).
	if err := bob.DeleteBlob(t.Context(), att.BlobID); err != nil {
		t.Errorf("deleting an already-released claim must be success, got %v", err)
	}
}

// A download that fails must not release anything: the bytes never reached
// disk, so the server copy is still the only one there is.
func TestAFailedDownloadKeepsTheClaim(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	att, messageID, aliceID := sendPictureTo(t, srv, alice, bob)

	// Arrives, but will not open -- the ciphertext is damaged in place, so the
	// GET succeeds and the decrypt is what fails.
	srv.set(func(s *fakeServer) {
		damaged := append([]byte(nil), s.blobs[att.BlobID]...)
		damaged[len(damaged)-1] ^= 0xff
		s.blobs[att.BlobID] = damaged
	})

	if _, err := bob.EnsureAttachment(t.Context(), aliceID, messageID, "", att); err == nil {
		t.Fatal("a blob that does not open must be an error, not silent success")
	}
	if got := srv.blobRecipientsFor(att.BlobID); len(got) != 1 {
		t.Errorf("nothing was stored, so the claim must remain, got %v", got)
	}
}

// A cache hit never touches the server, so it cannot release a claim either --
// including the claim of some *other* device, which is what asking blindly
// would risk.
func TestACachedAttachmentReleasesNothing(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	att, messageID, aliceID := sendPictureTo(t, srv, alice, bob)

	// Already on disk, as it would be for a sender or after an earlier fetch.
	if err := bob.WriteAttachmentFile(aliceID, messageID, imageBytes()); err != nil {
		t.Fatalf("WriteAttachmentFile: %v", err)
	}

	if _, err := bob.EnsureAttachment(t.Context(), aliceID, messageID, "", att); err != nil {
		t.Fatalf("EnsureAttachment: %v", err)
	}
	if got := srv.blobRecipientsFor(att.BlobID); len(got) != 1 {
		t.Errorf("a cache hit must leave the server alone, claims now %v", got)
	}
}

// A blob that is gone costs its own picture and nothing else. The account may
// have been deleted outright, the blob expired, the sender removed it.
func TestAMissingBlobDoesNotCostTheMessage(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	aliceID := identityOf(t, alice).AccountID
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	sent, err := alice.SendText(t.Context(), bobID, "with a caption", SendOptions{
		Media: &OutgoingMedia{Bytes: imageBytes(), MimeType: "image/jpeg", Thumb: []byte("tiny")},
	})
	if err != nil {
		t.Fatalf("SendText: %v", err)
	}
	got := deliverTo(t, bob)

	// Gone between the message arriving and anybody looking at it.
	srv.set(func(s *fakeServer) { s.blobs = map[string][]byte{} })

	_, err = bob.EnsureAttachment(t.Context(), aliceID, got[0].StoredMessageID, "", got[0].Content.Attachments[0])
	var unavailable *ErrBlobUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("want ErrBlobUnavailable so the caller can show a placeholder instead of retrying, got %v", err)
	}

	// The message itself is untouched, caption, preview and all.
	msgs, err := bob.Messages(aliceID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Text != "with a caption" {
		t.Fatalf("the message must survive its picture: %+v", msgs)
	}
	thumb, _ := bob.AttachmentThumb(aliceID, got[0].StoredMessageID)
	if string(thumb) != "tiny" {
		t.Error("the inline preview is local and must outlive the blob")
	}
	_ = sent
}

// A blob decrypts only with its own key, and a wrong one is a failure rather
// than plausible-looking bytes.
func TestABlobDoesNotOpenWithTheWrongKey(t *testing.T) {
	original := imageBytes()
	key, ciphertext, digest, err := sealAttachment(original)
	if err != nil {
		t.Fatalf("sealAttachment: %v", err)
	}
	if digest == "" {
		t.Error("the upload signs over the digest, so one has to be produced here")
	}
	back, err := openAttachment(key, ciphertext)
	if err != nil || !bytes.Equal(back, original) {
		t.Fatalf("round trip failed: %v", err)
	}

	wrong := append([]byte(nil), key...)
	wrong[0] ^= 0xff
	if _, err := openAttachment(wrong, ciphertext); err == nil {
		t.Error("a wrong key must fail, not return garbage")
	}
	// Tampering is authenticated against, so a modified blob is refused too.
	damaged := append([]byte(nil), ciphertext...)
	damaged[len(damaged)-1] ^= 0xff
	if _, err := openAttachment(key, damaged); err == nil {
		t.Error("a tampered blob must fail to open")
	}
	if _, err := openAttachment(key, ciphertext[:5]); err == nil {
		t.Error("a blob shorter than its own nonce must fail cleanly")
	}
}

// An upload that failed leaves the picture on disk, and the retry finishes the
// job -- including in a later run of the process.
func TestARetryFinishesAnUploadThatFailed(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	aliceID := identityOf(t, alice).AccountID
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}

	srv.set(func(s *fakeServer) { s.blobStatus = http.StatusServiceUnavailable })
	original := imageBytes()
	failed, err := alice.SendText(t.Context(), bobID, "with a picture", SendOptions{
		Media: &OutgoingMedia{Bytes: original, MimeType: "image/jpeg", Thumb: []byte("tiny")},
	})
	if err == nil {
		t.Fatal("the send must fail when its upload does")
	}
	if srv.queueLen("bob") != 0 {
		t.Fatal("nothing may be sent when the picture never got there")
	}

	// The line is there, failed, with a preview and no blob -- which is what a
	// retry needs to know it has work to do.
	msgs, err := alice.Messages(bobID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	line := msgs[len(msgs)-1]
	if line.SendState != SendFailed {
		t.Fatalf("send state: want %q, got %q", SendFailed, line.SendState)
	}
	if len(line.Attachments) != 1 || line.Attachments[0].BlobID != "" {
		t.Fatalf("want a placeholder attachment with no blob, got %+v", line.Attachments)
	}

	// Re-opened, as after a restart: the bytes have to come off disk, not out
	// of a field somebody kept in memory.
	reopened, err := Open(alice.Path())
	if err != nil {
		t.Fatalf("re-opening: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	srv.set(func(s *fakeServer) { s.blobStatus = 0 })
	retried, err := reopened.RetryMessage(t.Context(), bobID, failed.Message.ID)
	if err != nil {
		t.Fatalf("RetryMessage: %v", err)
	}
	if len(retried.Message.Attachments) != 1 || retried.Message.Attachments[0].BlobID == "" {
		t.Fatalf("the retry must upload and name the blob, got %+v", retried.Message.Attachments)
	}

	got := deliverTo(t, bob)
	if len(got) != 1 || len(got[0].Content.Attachments) != 1 {
		t.Fatalf("bob received %+v", got)
	}
	fetched, err := bob.EnsureAttachment(t.Context(), aliceID, got[0].StoredMessageID, "", got[0].Content.Attachments[0])
	if err != nil {
		t.Fatalf("EnsureAttachment: %v", err)
	}
	if !bytes.Equal(fetched, original) {
		t.Error("the retried picture differs from the original")
	}
}

// When the upload worked and only the message failed, the retry names the same
// blob instead of leaving a second copy nobody references.
func TestARetryDoesNotUploadTheSameBlobTwice(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}

	srv.set(func(s *fakeServer) { s.sendStatus = http.StatusServiceUnavailable })
	failed, err := alice.SendText(t.Context(), bobID, "picture", SendOptions{
		Media: &OutgoingMedia{Bytes: imageBytes(), MimeType: "image/jpeg"},
	})
	if err == nil {
		t.Fatal("the send must fail")
	}
	if got := srv.blobCount(); got != 1 {
		t.Fatalf("the upload succeeded, so there should be one blob, got %d", got)
	}

	srv.set(func(s *fakeServer) { s.sendStatus = 0 })
	if _, err := alice.RetryMessage(t.Context(), bobID, failed.Message.ID); err != nil {
		t.Fatalf("RetryMessage: %v", err)
	}
	if got := srv.blobCount(); got != 1 {
		t.Errorf("the retry uploaded the picture again: %d blobs for one message", got)
	}
	if got := deliverTo(t, bob); len(got) != 1 || len(got[0].Content.Attachments) != 1 {
		t.Fatalf("bob received %+v", got)
	}
}

// The one case that has to refuse: no blob on the server, and no bytes here
// either. Sending the caption alone would deliver something never composed.
func TestARetryRefusesWhenThePictureIsGone(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}

	srv.set(func(s *fakeServer) { s.blobStatus = http.StatusServiceUnavailable })
	failed, err := alice.SendText(t.Context(), bobID, "with a picture", SendOptions{
		Media: &OutgoingMedia{Bytes: imageBytes(), MimeType: "image/jpeg"},
	})
	if err == nil {
		t.Fatal("the send must fail")
	}

	// The local copy is cleared -- storage reclaimed, media wiped, a restore
	// onto another device.
	if err := alice.DeleteChatMedia(bobID); err != nil {
		t.Fatalf("DeleteChatMedia: %v", err)
	}

	srv.set(func(s *fakeServer) { s.blobStatus = 0 })
	if _, err := alice.RetryMessage(t.Context(), bobID, failed.Message.ID); !errors.Is(err, ErrAttachmentNotResendable) {
		t.Fatalf("want ErrAttachmentNotResendable, got %v", err)
	}
	if srv.queueLen("bob") != 0 {
		t.Error("nothing may be sent when the picture cannot be reproduced")
	}
}

// Blocking is a rule about state, not about a screen: nothing goes to a
// blocked contact from any path.
func TestNothingIsSentToABlockedContact(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	if _, err := alice.SendText(t.Context(), bobID, "before the block", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	deliverTo(t, bob)

	if err := alice.BlockPeer(bobID, ""); err != nil {
		t.Fatalf("BlockPeer: %v", err)
	}
	queued := srv.queueLen("bob")

	if _, err := alice.SendText(t.Context(), bobID, "after", SendOptions{}); !errors.Is(err, ErrPeerBlocked) {
		t.Errorf("SendText to a blocked contact: want ErrPeerBlocked, got %v", err)
	}
	// A receipt is the one that would slip through a screen-level rule: it is
	// sent by machinery, not by a person pressing anything.
	if err := alice.SendReceipt(t.Context(), bobID, ReceiptRead, time.Now()); !errors.Is(err, ErrPeerBlocked) {
		t.Errorf("SendReceipt to a blocked contact: want ErrPeerBlocked, got %v", err)
	}
	if err := alice.ResetSession(t.Context(), bobID, RekeyUserRequested); !errors.Is(err, ErrPeerBlocked) {
		t.Errorf("ResetSession with a blocked contact: want ErrPeerBlocked, got %v", err)
	}
	if got := srv.queueLen("bob"); got != queued {
		t.Errorf("%d envelope(s) reached a blocked contact", got-queued)
	}

	// Nothing was written for the refused message either: a blocked peer must
	// not leave a failed line in a transcript nobody asked to write to.
	msgs, err := alice.Messages(bobID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	for _, m := range msgs {
		if m.Text == "after" {
			t.Error("a refused message must not be recorded")
		}
	}

	// Unblocking restores it.
	if err := alice.UnblockPeer(bobID); err != nil {
		t.Fatalf("UnblockPeer: %v", err)
	}
	if _, err := alice.SendText(t.Context(), bobID, "after unblocking", SendOptions{}); err != nil {
		t.Fatalf("SendText after unblocking: %v", err)
	}
}

// Media can live outside the account directory, because pictures are the one
// thing here that is large and platform-opinionated.
func TestMediaCanLiveOutsideTheAccountDirectory(t *testing.T) {
	dir := t.TempDir()
	accountPath := filepath.Join(dir, "account")
	mediaPath := filepath.Join(dir, "elsewhere", "pictures")

	c, err := OpenWith(accountPath, Options{MediaPath: mediaPath})
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if err := c.WriteAttachmentFile("fz1peer", "msg-1", []byte("bytes")); err != nil {
		t.Fatalf("WriteAttachmentFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mediaPath, "fz1peer", "msg-1")); err != nil {
		t.Errorf("the file did not land under the configured media path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(accountPath, "media")); !os.IsNotExist(err) {
		t.Error("nothing should have been written under the account directory")
	}

	// And the default still works, next to the account.
	plain, err := Open(filepath.Join(dir, "default"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = plain.Close() })
	if err := plain.WriteAttachmentFile("fz1peer", "msg-1", []byte("bytes")); err != nil {
		t.Fatalf("WriteAttachmentFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "default", "media", "fz1peer", "msg-1")); err != nil {
		t.Errorf("the default media path is not under the account: %v", err)
	}
}

// Ids reaching the media store come off the wire in some paths, so a peer that
// names "../" must not be able to write outside it.
func TestMediaRefusesIdsThatEscapeTheStore(t *testing.T) {
	c, err := Open(filepath.Join(t.TempDir(), "account"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	for _, tc := range []struct{ chat, message string }{
		{"..", "msg"},
		{"fz1peer", ".."},
		{"a/b", "msg"},
		{"fz1peer", "a\\b"},
		{"", "msg"},
	} {
		if err := c.WriteAttachmentFile(tc.chat, tc.message, []byte("x")); err == nil {
			t.Errorf("chat %q message %q was accepted", tc.chat, tc.message)
		}
	}
}
