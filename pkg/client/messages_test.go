package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func at(minute int) time.Time {
	return time.Date(2026, 8, 7, 9, minute, 0, 0, time.UTC)
}

func TestMessageRoundTripWithChildren(t *testing.T) {
	c := openTestClient(t)
	sentAt := at(1)
	replyMine := true

	want := Message{
		ID:                   "m1",
		Text:                 "look at this",
		Mine:                 true,
		Timestamp:            at(2),
		SenderSentAt:         &sentAt,
		SenderAccountID:      "fz1author",
		ReplyToID:            "m0",
		ReplyPreviewText:     "what was it?",
		ReplyPreviewMine:     &replyMine,
		ReplyPreviewAuthorID: "fz1other",
		Kind:                 MessageNormal,
		SendState:            SendSent,
		Attachments: []Attachment{{
			Kind: "image", Algorithm: "aes-256-gcm", BlobID: "blob-1",
			Key: []byte{1, 2, 3}, MimeType: "image/jpeg",
			ByteSize: 4096, Width: 800, Height: 600, Thumb: []byte{9, 9},
		}},
		Deliveries: []GroupDelivery{
			{AccountID: "fz1a", WireMessageID: "w-a", State: SendSent},
			{AccountID: "fz1b", WireMessageID: "w-b", State: SendFailed, AttachmentSkipped: true},
		},
	}
	if err := c.AppendMessage("chat", want); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	msgs, err := c.Messages("chat")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("transcript length: want 1, got %d", len(msgs))
	}
	got := msgs[0]

	if !got.Timestamp.Equal(want.Timestamp) {
		t.Errorf("timestamp: want %v, got %v", want.Timestamp, got.Timestamp)
	}
	if got.SenderSentAt == nil || !got.SenderSentAt.Equal(sentAt) {
		t.Errorf("sender_sent_at: want %v, got %v", sentAt, got.SenderSentAt)
	}
	if got.ReplyPreviewMine == nil || *got.ReplyPreviewMine != replyMine {
		t.Errorf("reply preview mine: want %v, got %v", replyMine, got.ReplyPreviewMine)
	}
	if got.ReplyToID != want.ReplyToID || got.ReplyPreviewText != want.ReplyPreviewText {
		t.Errorf("reply snapshot lost: %+v", got)
	}
	if len(got.Attachments) != 1 {
		t.Fatalf("attachments: want 1, got %d", len(got.Attachments))
	}
	if fmt.Sprint(got.Attachments[0]) != fmt.Sprint(want.Attachments[0]) {
		t.Errorf("attachment:\n got %+v\nwant %+v", got.Attachments[0], want.Attachments[0])
	}
	if len(got.Deliveries) != 2 {
		t.Fatalf("deliveries: want 2, got %d", len(got.Deliveries))
	}
	if !got.Deliveries[1].AttachmentSkipped {
		t.Error("attachment_skipped did not survive -- the bubble would stop saying they never got the picture")
	}
}

// The transcript's order is arrival order. A message decrypted late carries an
// older timestamp and still belongs where it arrived; ordering by time would
// rearrange exactly those transcripts, and a system line has no sender clock at
// all to be ordered by.
func TestTranscriptKeepsArrivalOrderNotTimeOrder(t *testing.T) {
	c := openTestClient(t)
	for _, m := range []Message{
		{ID: "first", Text: "one", Timestamp: at(30)},
		{ID: "late", Text: "two", Timestamp: at(10)}, // older, arrived second
		{ID: "third", Text: "three", Timestamp: at(20)},
	} {
		if err := c.AppendMessage("chat", m); err != nil {
			t.Fatalf("AppendMessage: %v", err)
		}
	}

	msgs, err := c.Messages("chat")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	got := []string{}
	for _, m := range msgs {
		got = append(got, m.ID)
	}
	want := []string{"first", "late", "third"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("transcript order: want %v, got %v -- this is arrival order, not timestamp order", want, got)
	}

	last, err := c.LastMessage("chat")
	if err != nil {
		t.Fatalf("LastMessage: %v", err)
	}
	if last == nil || last.ID != "third" {
		t.Errorf("last message: want third, got %v", last)
	}
}

func TestLastMessageOnEmptyChat(t *testing.T) {
	c := openTestClient(t)
	last, err := c.LastMessage("nobody")
	if err != nil {
		t.Fatalf("LastMessage: %v", err)
	}
	if last != nil {
		t.Errorf("empty chat should have no last message, got %+v", last)
	}
}

// Nothing is in flight in a process that no longer exists -- but a send that is
// genuinely in flight in *this* process must keep reading back as pending.
func TestPendingSurvivesTheSessionAndFailsOnReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.db")
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := c.AppendMessage("chat", Message{
		ID: "m1", Text: "sending...", Mine: true, Timestamp: at(1),
		SendState: SendPending,
		Deliveries: []GroupDelivery{
			{AccountID: "fz1a", WireMessageID: "w-a", State: SendPending},
		},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Same process: the upload really is running, so the bubble must still say so.
	msgs, err := c.Messages("chat")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if msgs[0].SendState != SendPending {
		t.Errorf("in-session send state: want %q, got %q -- a live upload was reported as finished", SendPending, msgs[0].SendState)
	}
	if msgs[0].Deliveries[0].State != SendPending {
		t.Errorf("in-session delivery state: want %q, got %q", SendPending, msgs[0].Deliveries[0].State)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// New process: that send cannot still be running, so it is a failure to retry.
	c2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer c2.Close()

	msgs, err = c2.Messages("chat")
	if err != nil {
		t.Fatalf("Messages after reopen: %v", err)
	}
	if msgs[0].SendState != SendFailed {
		t.Errorf("send state after reopen: want %q, got %q -- a spinner nobody will ever resolve", SendFailed, msgs[0].SendState)
	}
	if msgs[0].Deliveries[0].State != SendFailed {
		t.Errorf("delivery state after reopen: want %q, got %q", SendFailed, msgs[0].Deliveries[0].State)
	}
}

func TestSetSendStateAndDeliveryState(t *testing.T) {
	c := openTestClient(t)
	if err := c.AppendMessage("chat", Message{
		ID: "m1", Timestamp: at(1), SendState: SendPending,
		Deliveries: []GroupDelivery{
			{AccountID: "fz1a", WireMessageID: "w-a", State: SendPending},
			{AccountID: "fz1b", WireMessageID: "w-b", State: SendPending},
		},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	if err := c.SetMessageSendState("chat", "m1", SendSent); err != nil {
		t.Fatalf("SetMessageSendState: %v", err)
	}
	// A group send is N states, and a retry addresses only the ones that failed.
	if err := c.SetGroupDeliveryState("chat", "m1", "fz1b", SendFailed, "their server said no"); err != nil {
		t.Fatalf("SetGroupDeliveryState: %v", err)
	}

	last, err := c.LastMessage("chat")
	if err != nil {
		t.Fatalf("LastMessage: %v", err)
	}
	if last.SendState != SendSent {
		t.Errorf("send state: want %q, got %q", SendSent, last.SendState)
	}
	byAccount := map[string]GroupDelivery{}
	for _, d := range last.Deliveries {
		byAccount[d.AccountID] = d
	}
	if byAccount["fz1a"].State != SendPending || byAccount["fz1b"].State != SendFailed {
		t.Errorf("per-recipient states not independent: %+v", byAccount)
	}
	// The reason rides with the state, so a sheet can say why rather than only
	// that -- and it survives being replayed from the log.
	if got := byAccount["fz1b"].Error; got != "their server said no" {
		t.Errorf("failure reason: want %q, got %q", "their server said no", got)
	}
	if got := byAccount["fz1a"].Error; got != "" {
		t.Errorf("a copy that did not fail must carry no reason, got %q", got)
	}

	// Succeeding later clears it: a reason that outlives its failure is worse
	// than none.
	if err := c.SetGroupDeliveryState("chat", "m1", "fz1b", SendSent, ""); err != nil {
		t.Fatalf("SetGroupDeliveryState again: %v", err)
	}
	last, err = c.LastMessage("chat")
	if err != nil {
		t.Fatalf("LastMessage: %v", err)
	}
	for _, d := range last.Deliveries {
		if d.AccountID == "fz1b" && (d.State != SendSent || d.Error != "") {
			t.Errorf("a copy that arrived still carries a failure: %+v", d)
		}
	}
}

func TestDeleteMessageTakesItsChildrenWithIt(t *testing.T) {
	c := openTestClient(t)
	if err := c.AppendMessage("chat", Message{
		ID: "m1", Timestamp: at(1),
		Attachments: []Attachment{{Kind: "image", BlobID: "b", Key: []byte{1}}},
		Deliveries:  []GroupDelivery{{AccountID: "fz1a", WireMessageID: "w", State: SendSent}},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := c.PinMessage("chat", "m1"); err != nil {
		t.Fatalf("PinMessage: %v", err)
	}

	if err := c.DeleteMessage("chat", "m1"); err != nil {
		t.Fatalf("DeleteMessage: %v", err)
	}

	msgs, err := c.Messages("chat")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("message survived deletion: %+v", msgs)
	}
	pins, err := c.PinnedMessageIDs("chat")
	if err != nil {
		t.Fatalf("PinnedMessageIDs: %v", err)
	}
	if len(pins) != 0 {
		t.Errorf("pin outlived its message: %v", pins)
	}

	// Re-appending the same id must not turn up the deleted attachments and
	// deliveries, which would happen if the cascade had left orphans behind.
	if err := c.AppendMessage("chat", Message{ID: "m1", Timestamp: at(2)}); err != nil {
		t.Fatalf("re-appending: %v", err)
	}
	last, err := c.LastMessage("chat")
	if err != nil {
		t.Fatalf("LastMessage: %v", err)
	}
	if len(last.Attachments) != 0 || len(last.Deliveries) != 0 {
		t.Errorf("orphaned children resurfaced: %d attachments, %d deliveries",
			len(last.Attachments), len(last.Deliveries))
	}
}

func TestClearTranscriptKeepsEverythingElse(t *testing.T) {
	c := openTestClient(t)
	if err := c.PutConversation(Conversation{PeerAccountID: "peer"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}
	if err := c.SetSession("peer", Sending, newTestSession(t)); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	if err := c.AppendMessage("peer", Message{ID: "m1", Timestamp: at(1)}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	if err := c.ClearTranscript("peer"); err != nil {
		t.Fatalf("ClearTranscript: %v", err)
	}

	msgs, _ := c.Messages("peer")
	if len(msgs) != 0 {
		t.Error("transcript not cleared")
	}
	if convo, _ := c.Conversation("peer"); convo == nil {
		t.Error("clearing the history removed the conversation")
	}
	if s, _ := c.Session("peer", Sending); s == nil {
		t.Error("clearing the history removed the ratchet session")
	}
}

func TestPinsAreOrderedOldestFirstAndRePinningDoesNotMove(t *testing.T) {
	c := openTestClient(t)
	for _, id := range []string{"a", "b", "cee"} {
		if err := c.AppendMessage("chat", Message{ID: id, Timestamp: at(1)}); err != nil {
			t.Fatalf("AppendMessage: %v", err)
		}
	}
	for _, id := range []string{"cee", "a"} {
		if err := c.PinMessage("chat", id); err != nil {
			t.Fatalf("PinMessage: %v", err)
		}
	}
	// Pinning something already pinned must leave its place alone, or the
	// sticky bar's "most recently pinned" jumps for no reason the user caused.
	if err := c.PinMessage("chat", "cee"); err != nil {
		t.Fatalf("re-pinning: %v", err)
	}

	pins, err := c.PinnedMessageIDs("chat")
	if err != nil {
		t.Fatalf("PinnedMessageIDs: %v", err)
	}
	if fmt.Sprint(pins) != fmt.Sprint([]string{"cee", "a"}) {
		t.Errorf("pin order: want [cee a], got %v", pins)
	}

	if err := c.UnpinMessage("chat", "cee"); err != nil {
		t.Fatalf("UnpinMessage: %v", err)
	}
	pins, _ = c.PinnedMessageIDs("chat")
	if fmt.Sprint(pins) != fmt.Sprint([]string{"a"}) {
		t.Errorf("after unpin: want [a], got %v", pins)
	}
}

// chat_id is one namespace for peers and groups alike, following the app: both
// ids are 21-character bech32m strings differing only in a version marker. Two
// chats must still not see each other's lines.
func TestTranscriptsAreSeparatePerChat(t *testing.T) {
	c := openTestClient(t)
	if err := c.AppendMessage("fz1peer", Message{ID: "m1", Text: "to a person", Timestamp: at(1)}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := c.AppendMessage("fz2group", Message{ID: "m1", Text: "to a group", Timestamp: at(1)}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// The same message id in two chats is not a collision.
	person, err := c.LastMessage("fz1peer")
	if err != nil {
		t.Fatalf("LastMessage: %v", err)
	}
	group, err := c.LastMessage("fz2group")
	if err != nil {
		t.Fatalf("LastMessage: %v", err)
	}
	if person.Text != "to a person" || group.Text != "to a group" {
		t.Errorf("chats are sharing rows: %q / %q", person.Text, group.Text)
	}

	if err := c.ClearTranscript("fz1peer"); err != nil {
		t.Fatalf("ClearTranscript: %v", err)
	}
	if msgs, _ := c.Messages("fz2group"); len(msgs) != 1 {
		t.Error("clearing one chat emptied another")
	}
}

// The chat-list preview reads a bounded window, not the whole transcript.
//
// Asserted structurally rather than by timing: a stopwatch here measures the
// machine, and an earlier attempt at one passed happily against a deliberately
// reintroduced full replay -- it could not tell the two apart at any size the
// test could afford to build. Bytes read is the actual property.
func TestTailLinesReadsOnlyTheTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.jsonl")

	// The window is measured in bytes, so a few big records exceed it as surely
	// as many small ones -- and every append costs an fsync, which is right for
	// a message arriving but wrong for a test writing thousands.
	const records = 400
	filler := strings.Repeat("x", 2048)
	for i := 0; i < records; i++ {
		if err := appendLine(path, logRecord{
			T: recMessage, ID: fmt.Sprintf("m%06d", i), Text: filler,
			Timestamp: at(1).UTC().Format(time.RFC3339Nano),
		}); err != nil {
			t.Fatalf("appendLine: %v", err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() <= maxTailBytes {
		t.Fatalf("test log is only %d bytes; it has to exceed the %d-byte window to prove anything",
			info.Size(), maxTailBytes)
	}

	lines, found, err := tailLines(path)
	if err != nil {
		t.Fatalf("tailLines: %v", err)
	}
	if !found {
		t.Fatal("no records returned from a log full of them")
	}

	read := 0
	for _, l := range lines {
		read += len(l) + 1
	}
	if read > maxTailBytes {
		t.Errorf("read %d bytes, more than the %d-byte window", read, maxTailBytes)
	}
	if int64(read) >= info.Size() {
		t.Errorf("read %d of %d bytes -- that is the whole file, not its tail", read, info.Size())
	}

	// Newest first, and the newest is the last one written.
	var newest logRecord
	if err := json.Unmarshal(lines[0], &newest); err != nil {
		t.Fatalf("decoding newest record: %v", err)
	}
	if want := fmt.Sprintf("m%06d", records-1); newest.ID != want {
		t.Errorf("newest record: want %s, got %s", want, newest.ID)
	}
}

// And the preview itself stays correct on a transcript far larger than the
// window -- the bound is only worth having if the answer is still right.
func TestLastMessageIsCorrectOnALogBeyondTheWindow(t *testing.T) {
	c := openTestClient(t)
	filler := strings.Repeat("x", 2048)
	for i := 0; i < 400; i++ {
		if err := c.AppendMessage("chat", Message{
			ID: fmt.Sprintf("m%06d", i), Text: filler, Timestamp: at(1),
		}); err != nil {
			t.Fatalf("AppendMessage: %v", err)
		}
	}

	last, err := c.LastMessage("chat")
	if err != nil {
		t.Fatalf("LastMessage: %v", err)
	}
	if last == nil || last.ID != "m000399" {
		t.Fatalf("last message: want m000399, got %v", last)
	}
}
