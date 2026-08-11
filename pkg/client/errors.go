package client

import (
	"errors"
	"fmt"
)

// APIError is a Freizone server refusing a request in its own JSON error
// format (`{"error": {"code": ..., "message": ...}}`).
type APIError struct {
	StatusCode int

	// Code is the server's machine-readable classification, empty when the
	// body carried none. Empty means undiagnosed, never harmless.
	Code string

	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("client: server returned %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("client: server returned %d (%s): %s", e.StatusCode, e.Code, e.Message)
}

// NotFreizoneServerError reports a host that answered, but not in the JSON
// every Freizone server speaks -- almost always an address that resolved to
// something else entirely: a parked page, a plain web server's HTML 404, a
// reverse proxy.
//
// Deliberately distinct from [APIError], which is a real Freizone server
// refusing a request. This one means "wrong server", so a caller can point the
// user at the address they typed instead of showing them a raw HTML page.
type NotFreizoneServerError struct {
	StatusCode int
	Host       string
}

func (e *NotFreizoneServerError) Error() string {
	return fmt.Sprintf("client: %s did not answer as a Freizone server (HTTP %d)", e.Host, e.StatusCode)
}

// enqueueError is one copy's per-item batch status (PROTOCOL.md §7) saying the
// recipient's server did not take it. A type rather than a formatted string so
// the status survives to whoever has to phrase it for a reader -- the batch
// answers `queue_full` and `unknown_recipient` to two very different people.
type enqueueError struct{ Status string }

func (e *enqueueError) Error() string {
	return fmt.Sprintf("their server answered %q", e.Status)
}

// IsStaleDevice reports whether err is a server saying the device id it was
// given is dead -- PROTOCOL.md §4's stale-device rule.
//
// Servers carrying the distinct codes answer `unknown_device`,
// `no_prekey_bundle` or `unknown_recipient`; servers from before the rule
// answer all of those with the catch-all `not_found`, so any other 404 counts
// too. The one explicit exception is `federation_disabled`, which is about the
// server and never about the device.
//
// Both directions of getting this wrong cost something real. Too narrow, and a
// peer who re-created their account stays undeliverable forever: every send
// claims a bundle for a device id their server has long forgotten, 404s, and
// nothing heals. Too wide, and a 404 that says nothing about the device costs a
// perfectly good cached device and its ratchet session, forcing a needless
// re-key.
func IsStaleDevice(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == 404 && apiErr.Code != "federation_disabled"
}

// IsStaleRecipientStatus is the batch form of the same discovery: whether one
// copy's per-item status (PROTOCOL.md §7) says its recipient device is gone.
// Only `unknown_recipient` does -- `queue_full`, `invalid` and `internal_error`
// all describe conditions a retry against the same device can outlive.
func IsStaleRecipientStatus(status string) bool { return status == "unknown_recipient" }

// IsDeliveredStatus reports whether one copy's per-item status means the
// recipient's server took it.
//
// Two of them do. `queued` is the ordinary answer -- the server holds the
// envelope until that device fetches it, which is what delivery *is* here,
// since nothing waits for the recipient to be online. `duplicate` means it
// already had this message id, which is the answer a retry is built to get:
// posting under the id a previous attempt used is how a second attempt avoids
// delivering the same message twice.
//
// Everything else -- `invalid`, `unknown_recipient`, `queue_full`,
// `internal_error` -- is a copy that did not arrive. A status this build does
// not know counts as failure too: inventing success for an answer we cannot
// read would record a message as delivered on the strength of not
// understanding the reply.
func IsDeliveredStatus(status string) bool {
	return status == "queued" || status == "duplicate"
}
