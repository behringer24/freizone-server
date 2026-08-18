package client

import (
	"context"
	"errors"
	"fmt"
)

// What a caller owes an envelope, and what it owes a fresh connection.
//
// [Client.HandleIncoming] deliberately does no network I/O: it decrypts, folds
// and stores, and stops. Everything that follows from what it found -- telling
// the server the envelope was handled, confirming it to its sender, answering a
// group peer whose view has drifted -- is left to the caller, because those are
// requests and the receive path is not allowed to make any.
//
// Left to the caller, and then written out by every caller identically. This
// file is where that stops. It existed once before, in freizone-app's FFI
// layer, shared between the app's live poll loop and its background wake --
// and nothing else could reach it, so a bot would have been a third copy of
// rules that are easy to get subtly wrong and expensive to get wrong at all:
//
//   - Acknowledge on any result, and on a failure that has been given up on,
//     but never otherwise. A decrypt failure is deterministic, so a poison
//     envelope that is never acknowledged blocks everything behind it for as
//     long as the queue holds it.
//   - Do not confirm a duplicate. Redelivery is routine, and a receipt for one
//     would move a watermark the sender has already watched move. Today the
//     receive path also returns nothing to confirm *with* for a duplicate, so
//     the check below is a second line rather than the only one -- but the two
//     are independent, and a caller that skips it is relying on a property of
//     a different file.
//   - Answer a group's drift where it was noticed, rather than leaving it to
//     the next envelope that happens to carry a hash.

// DrainFailure is one envelope that could not be read.
type DrainFailure struct {
	MessageID       string
	SenderAccountID string
	Err             error

	// Acknowledged reports that the envelope was given up on and taken off the
	// server's queue. False means it is still there and will come again --
	// which is the point, for a failure a later attempt can still resolve.
	Acknowledged bool
}

func (f DrainFailure) Error() string {
	return fmt.Sprintf("client: envelope %s from %s: %v", f.MessageID, f.SenderAccountID, f.Err)
}

// DrainReport is what one pass over the queue produced.
//
// Both halves are returned rather than the first error: a queue is a batch, and
// one unreadable envelope must not hide the twenty behind it that were fine.
type DrainReport struct {
	// Results are the envelopes that were read, in the order they arrived.
	// Duplicates are included and marked as such, since a caller counting
	// arrivals and a caller drawing them want different things from that.
	Results []ReceiveResult

	// Failures are the envelopes that were not.
	Failures []DrainFailure
}

// HandleAndAck runs one envelope through the receive path and does everything
// that follows from it: acknowledges it when the rule says to, confirms it to
// its sender, and answers a group peer whose view has drifted.
//
// The returned error is the receive failure, if there was one -- by then the
// envelope has already been acknowledged or left in place, per the rule. The
// follow-up requests are best-effort and never returned: a lost confirmation
// goes again from [Client.ResendPendingReceipts], and a group divergence
// unanswered here is answered on the next envelope that carries the hash.
func (c *Client) HandleAndAck(ctx context.Context, msg IncomingMessage, opts ReceiveOptions) (ReceiveResult, error) {
	res, err := c.HandleIncoming(msg, opts)

	var decryptErr *DecryptError
	gaveUp := errors.As(err, &decryptErr) && decryptErr.GaveUp
	if err == nil || gaveUp {
		// Best-effort by design (see AckMessage): a lost acknowledgement means
		// redelivery, which the duplicate check absorbs on the next attempt.
		_ = c.AckMessage(ctx, msg.MessageID)
	}
	if err != nil {
		return res, err
	}
	if res.Duplicate {
		return res, nil
	}

	c.confirm(ctx, res)
	if res.Group != nil {
		_ = c.ReconcileGroup(ctx, *res.Group, res.PeerAccountID)
	}
	return res, nil
}

// Drain fetches whatever the server is holding for this device and runs each
// envelope through [Client.HandleAndAck].
//
// This is what a caller does on a fresh connection, and the reason
// [Client.Stream] does not do it: a stream carries what arrives from now on,
// and everything queued while nothing was listening is still sitting there.
// Safe to run while the stream is live -- an envelope delivered both ways is
// recognised as the duplicate it is, by the id it was already marked with.
//
// A failure to reach the server at all is an error, since nothing was learned.
// A failure to read one envelope is not: it is in the report.
func (c *Client) Drain(ctx context.Context, opts ReceiveOptions) (DrainReport, error) {
	msgs, err := c.FetchMessages(ctx)
	if err != nil {
		return DrainReport{}, err
	}

	report := DrainReport{Results: make([]ReceiveResult, 0, len(msgs))}
	for _, msg := range msgs {
		res, err := c.HandleAndAck(ctx, msg, opts)
		if err != nil {
			var decryptErr *DecryptError
			report.Failures = append(report.Failures, DrainFailure{
				MessageID:       msg.MessageID,
				SenderAccountID: msg.SenderAccountID,
				Err:             err,
				Acknowledged:    errors.As(err, &decryptErr) && decryptErr.GaveUp,
			})
			continue
		}
		report.Results = append(report.Results, res)
	}
	return report, nil
}

// confirm tells a sender how far their messages got, when the result says so.
// One shape for a group and one for a one-to-one, because the two file their
// watermarks in different places -- a group per member, a chat per chat.
func (c *Client) confirm(ctx context.Context, res ReceiveResult) {
	if res.Group != nil {
		if res.Group.DeliveredUpTo == nil {
			return
		}
		_ = c.SendGroupReceipt(ctx, res.Group.GroupID, res.PeerAccountID, ReceiptDelivered, *res.Group.DeliveredUpTo)
		if res.Group.ReadUpTo != nil {
			_ = c.SendGroupReceipt(ctx, res.Group.GroupID, res.PeerAccountID, ReceiptRead, *res.Group.ReadUpTo)
		}
		return
	}
	if res.DeliveredUpTo == nil {
		return
	}
	_ = c.SendReceipt(ctx, res.PeerAccountID, ReceiptDelivered, *res.DeliveredUpTo)
	if res.ReadUpTo != nil {
		_ = c.SendReceipt(ctx, res.PeerAccountID, ReceiptRead, *res.ReadUpTo)
	}
}

// MaintenanceReport is what one round of upkeep did, and what it could not do.
type MaintenanceReport struct {
	PrekeysToppedUp bool
	DebtsPaid       int
	Recovered       []string
	ReceiptsResent  int

	// GoneMembers are group members whose account no longer exists. Reported
	// because this is the only moment anything finds out: their row stays in
	// the group until a moderator removes it, so nothing else will ever
	// mention them again.
	GoneMembers []string

	// Problems are the parts that failed. Upkeep is best-effort by nature --
	// one failing part must not stop the others -- so they are collected here
	// rather than returned as an error.
	Problems []error
}

// Maintain is everything that should happen on a fresh connection.
//
// One call rather than four, because the order is not the caller's to know and
// four separate calls means getting it right four times. Top up the prekey pool
// so somebody can start a conversation while this device is away; settle any
// group facts owed; re-establish the sessions the evidence says are broken; and
// re-send confirmations that never got out.
//
// Worth running on a timer as well as on connect, for anything long-lived. A
// phone reconnects constantly and needs no timer; a process holding one stream
// open for weeks would otherwise never do any of this again, and the prekey
// pool would drain toward empty with nothing to notice.
//
// Never returns an error: everything it does is best-effort, and whatever did
// not work is in the report.
func (c *Client) Maintain(ctx context.Context) MaintenanceReport {
	var out MaintenanceReport

	if err := c.TopUpOneTimePrekeys(ctx); err != nil {
		out.Problems = append(out.Problems, fmt.Errorf("topping up prekeys: %w", err))
	} else {
		out.PrekeysToppedUp = true
	}

	if paid, gone, err := c.PayGroupSnapshotDebts(ctx); err != nil {
		out.Problems = append(out.Problems, fmt.Errorf("settling group facts: %w", err))
	} else {
		out.DebtsPaid = paid
		out.GoneMembers = gone
	}

	if recovered, err := c.RecoverDesyncedSessions(ctx); err != nil {
		out.Problems = append(out.Problems, fmt.Errorf("recovering sessions: %w", err))
	} else {
		out.Recovered = recovered
	}

	// A confirmation lost to a failed send is not marked as sent, so it goes
	// again -- but only when there is something new to confirm, which a quiet
	// conversation may not offer for days. A fresh connection is when whatever
	// broke the last attempt has most likely passed.
	if resent, err := c.ResendPendingReceipts(ctx); err != nil {
		out.Problems = append(out.Problems, fmt.Errorf("re-sending receipts: %w", err))
	} else {
		out.ReceiptsResent = resent
	}

	return out
}
