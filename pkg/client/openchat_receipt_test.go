package client

import (
	"testing"
)

// A message that lands in the chat the user is looking at is read the moment
// it arrives, and the author has to be told so.
//
// This is the half of the open-chat rule that was missing. The receive path
// already treats an open chat as "do not mark this unread" -- correctly, the
// user is looking at it -- but that decision was never passed on, and read
// receipts are only ever sent when a chat is *opened*. So a message arriving
// into an already-open chat was never confirmed read: not then, because
// nothing sent one, and not later either, because opening the chat again
// finds no unread flag to act on. Reported 2026-08-14 as a group counter
// stuck at "Read by 2 of 3" with the third member showing "Received".
func TestAMessageIntoTheOpenChatIsConfirmedRead(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	groupID := groupWith(t, srv, alice, bob)
	if _, err := alice.SendGroupText(t.Context(), groupID, "schaust du gerade hin?", SendOptions{}); err != nil {
		t.Fatalf("SendGroupText: %v", err)
	}

	// Bob has the group on screen as it arrives, so its unread flag is
	// already clear -- opening it is what clears it, and that is the state
	// this whole case is about.
	if opened, err := bob.GroupChat(groupID); err == nil && opened != nil {
		opened.HasUnread = false
		if err := bob.PutGroupChat(*opened); err != nil {
			t.Fatalf("PutGroupChat: %v", err)
		}
	}

	envelopes, err := bob.FetchMessages(t.Context())
	if err != nil {
		t.Fatalf("FetchMessages: %v", err)
	}
	var confirmed bool
	for _, env := range envelopes {
		res, err := bob.HandleIncoming(env, ReceiveOptions{OpenChatID: groupID})
		if err != nil {
			t.Fatalf("HandleIncoming: %v", err)
		}
		if err := bob.AckMessage(t.Context(), env.MessageID); err != nil {
			t.Fatalf("AckMessage: %v", err)
		}
		if res.Group == nil {
			continue
		}
		// Exactly what the caller does with an outcome: confirm what it says
		// to confirm, and nothing it does not.
		if res.Group.DeliveredUpTo != nil {
			if err := bob.SendGroupReceipt(t.Context(), groupID, res.PeerAccountID, ReceiptDelivered, *res.Group.DeliveredUpTo); err != nil {
				t.Fatalf("SendGroupReceipt delivered: %v", err)
			}
		}
		if res.Group.ReadUpTo != nil {
			confirmed = true
			if err := bob.SendGroupReceipt(t.Context(), groupID, res.PeerAccountID, ReceiptRead, *res.Group.ReadUpTo); err != nil {
				t.Fatalf("SendGroupReceipt read: %v", err)
			}
		}
	}
	if !confirmed {
		t.Error("the outcome never said the message was read, so no caller could confirm it")
	}

	// The unread flag is deliberately not set for an open chat, which is
	// precisely why opening it later cannot repair this.
	chat, err := bob.GroupChat(groupID)
	if err != nil || chat == nil {
		t.Fatalf("bob GroupChat: %v, %v", chat, err)
	}
	if chat.HasUnread {
		t.Error("a message in the open chat must not be marked unread")
	}

	syncGroups(t, alice)
	authorChat, err := alice.GroupChat(groupID)
	if err != nil || authorChat == nil {
		t.Fatalf("alice GroupChat: %v, %v", authorChat, err)
	}
	receipt := authorChat.MemberReceipts[bobID]
	if receipt.ReadUpTo == nil {
		t.Fatalf("the author was never told bob read it: %+v", authorChat.MemberReceipts)
	}
}

// The same rule for a one-to-one chat, which had the same hole: its unread
// flag is skipped for the open chat too, and its read receipts likewise only
// ever went out when the chat was opened.
func TestADirectMessageIntoTheOpenChatIsConfirmedRead(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	aliceID := identityOf(t, alice).AccountID

	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	if _, err := alice.SendText(t.Context(), bobID, "bist du da?", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}

	envelopes, err := bob.FetchMessages(t.Context())
	if err != nil {
		t.Fatalf("FetchMessages: %v", err)
	}
	var confirmed bool
	for _, env := range envelopes {
		// Bob is looking at alice's chat as it lands.
		res, err := bob.HandleIncoming(env, ReceiveOptions{OpenChatID: aliceID})
		if err != nil {
			t.Fatalf("HandleIncoming: %v", err)
		}
		if res.ReadUpTo == nil {
			continue
		}
		confirmed = true
		if err := bob.SendReceipt(t.Context(), res.PeerAccountID, ReceiptRead, *res.ReadUpTo); err != nil {
			t.Fatalf("SendReceipt: %v", err)
		}
	}
	if !confirmed {
		t.Fatal("the outcome never said the message was read, so no caller could confirm it")
	}

	deliverTo(t, alice)
	convo, err := alice.Conversation(bobID)
	if err != nil || convo == nil {
		t.Fatalf("Conversation: %v, %v", convo, err)
	}
	if convo.PeerReadUpTo == nil {
		t.Error("the sender was never told it had been read")
	}
}

// The other half of the same rule: a chat that is *not* on screen must not
// confirm anything as read. Claiming a read the user never made is worse than
// a counter that lags.
func TestAMessageIntoAClosedChatIsNotConfirmedRead(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")

	groupID := groupWith(t, srv, alice, bob)
	if _, err := alice.SendGroupText(t.Context(), groupID, "und jetzt nicht", SendOptions{}); err != nil {
		t.Fatalf("SendGroupText: %v", err)
	}

	envelopes, err := bob.FetchMessages(t.Context())
	if err != nil {
		t.Fatalf("FetchMessages: %v", err)
	}
	for _, env := range envelopes {
		// Some other chat is on screen.
		res, err := bob.HandleIncoming(env, ReceiveOptions{OpenChatID: "qsomeoneelse00000000x"})
		if err != nil {
			t.Fatalf("HandleIncoming: %v", err)
		}
		if res.Group != nil && res.Group.ReadUpTo != nil {
			t.Error("a chat nobody is looking at must not report itself read")
		}
	}
}
