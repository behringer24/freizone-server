package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/profileclaim"
)

// ReportCategory is why an account is being reported. A fixed set, matching
// the server's: there is deliberately no free-text field anywhere in this
// feature -- free text on a server is a store of personal allegations, and a
// channel for writing at an operator that nothing moderates.
type ReportCategory string

const (
	ReportSpam       ReportCategory = "spam"
	ReportHarassment ReportCategory = "harassment"
	ReportFraud      ReportCategory = "fraud"
	ReportOther      ReportCategory = "other"
)

// ValidReportCategory reports whether c is one a server will accept.
func ValidReportCategory(c ReportCategory) bool {
	switch c {
	case ReportSpam, ReportHarassment, ReportFraud, ReportOther:
		return true
	}
	return false
}

// ErrReportsUnavailable reports that the server in question does not accept
// reports -- switched off by its operator, or too old to know about them. The
// caller's job is to not offer the action in the first place (ask
// [Client.ServerStatus] first); this is the backstop for the race where it was
// switched off between asking and sending.
var ErrReportsUnavailable = errors.New("client: this server does not accept reports")

// ReportOptions carries the choices a report screen collects beyond the
// category.
type ReportOptions struct {
	// AlsoTellTheirServer additionally files the report with the reported
	// account's own home server, for a peer that lives on another one.
	//
	// Off by default, and a deliberate choice rather than something that
	// happens quietly: it hands the reporter's address to an operator they do
	// not know and have no relationship with. Filing with one's *own* server
	// always happens either way -- that operator knows the reporter, and is
	// the one who can act on a federated account at all (by blocklisting it).
	//
	// Ignored for a peer on this account's own server, where there is only one
	// operator to tell.
	AlsoTellTheirServer bool
}

// Report tells an operator that peer is a problem.
//
// **The report is named.** The reporter's address is stored and shown to that
// server's staff, so they can come back and ask what happened -- which is the
// main thing an operator does with a report, and the reason this is not
// anonymous. A caller must say so before calling this, not after.
//
// The evidence sent is the profile claims that peer has asserted about *itself*
// (SRV-32), signed, exactly as they arrived. Never a local name the user gave
// them: that is a private note, often an unkind one, and it is stored somewhere
// else entirely so that it cannot be picked up here by accident.
//
// Nothing acts on a report by itself. It raises a counter and files a case for
// a person to look at, which is all a server can honestly do about a claim it
// has no way to verify -- the content it concerns is end-to-end encrypted.
func (c *Client) Report(ctx context.Context, peer string, category ReportCategory, opts ReportOptions) error {
	if !ValidReportCategory(category) {
		return fmt.Errorf("client: %q is not a reportable category", category)
	}
	endpoint, err := c.Endpoint(ctx, peer)
	if err != nil {
		return err
	}
	id, err := c.Identity()
	if err != nil {
		return err
	}
	if endpoint.AccountID == id.AccountID {
		return errors.New("client: an account cannot report itself")
	}

	evidence, err := c.reportEvidence(peer)
	if err != nil {
		return err
	}
	reported := address.Address{ID: endpoint.AccountID, Server: endpoint.Server}.String()

	// Our own server first, and unconditionally: it is the operator who knows
	// the reporter, and the only one who can act on a federated account from
	// here. Its failure is the one worth surfacing.
	err = c.do(ctx, request{
		method: http.MethodPost,
		path:   "/v1/reports",
		auth:   authDevice,
		body: map[string]any{
			"reported": reported,
			"category": string(category),
			"evidence": evidence,
		},
	}, nil)
	if err != nil {
		return reportError(err)
	}

	if !opts.AlsoTellTheirServer || !endpoint.Federated() {
		return nil
	}
	return reportError(c.postFederatedReport(ctx, endpoint.Server, reported, category, evidence))
}

// WithdrawReport takes back a report about peer.
//
// Somebody who bears responsibility for an accusation has to be able to change
// their mind, so this is always available. It withdraws from both servers a
// report may have gone to; a server that has none simply answers 404, which is
// not an error to report to anybody -- the outcome the user asked for is that
// no report of theirs stands, and it does not.
func (c *Client) WithdrawReport(ctx context.Context, peer string) error {
	endpoint, err := c.Endpoint(ctx, peer)
	if err != nil {
		return err
	}
	reported := address.Address{ID: endpoint.AccountID, Server: endpoint.Server}.String()

	err = ignoreNoSuchReport(c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/v1/reports/" + reported,
		auth:   authDevice,
	}, nil))
	if err != nil {
		return reportError(err)
	}
	if !endpoint.Federated() {
		return nil
	}

	id, err := c.Identity()
	if err != nil {
		return err
	}
	issuedAt := time.Now().UTC()
	cert, err := signDeviceCert(id, issuedAt)
	if err != nil {
		return err
	}
	return reportError(ignoreNoSuchReport(c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/v1/federation/reports/" + reported,
		server: endpoint.Server,
		auth:   authFederated,
		body:   federatedSenderBody(id, cert),
	}, nil)))
}

// reportEvidence is what this device holds that a moderator can check: the
// claims peer signed about its own name.
//
// Deliberately reads the claim store and nothing else. The contact name this
// user assigned lives in the app's own store and is never consulted here --
// two stores rather than one field precisely so that this function cannot
// reach the wrong one.
func (c *Client) reportEvidence(peer string) ([]profileclaim.Claim, error) {
	profile, err := c.PeerProfile(peer)
	if err != nil || profile == nil {
		return nil, err
	}
	return profile.Claims, nil
}

func (c *Client) postFederatedReport(
	ctx context.Context, server, reported string, category ReportCategory, evidence []profileclaim.Claim,
) error {
	id, err := c.Identity()
	if err != nil {
		return err
	}
	issuedAt := time.Now().UTC()
	cert, err := signDeviceCert(id, issuedAt)
	if err != nil {
		return err
	}

	body := federatedSenderBody(id, cert)
	// The home server has no counterpart in federated message delivery, where
	// it travels inside the encrypted payload. A report has no such channel and
	// needs it anyway: naming a reporter is pointless if the operator cannot
	// reach them.
	body["sender_server"] = id.Server
	body["reported"] = reported
	body["category"] = string(category)
	body["evidence"] = evidence

	return c.do(ctx, request{
		method: http.MethodPost,
		path:   "/v1/federation/reports",
		server: server,
		auth:   authFederated,
		body:   body,
	}, nil)
}

// federatedSenderBody is the inline identity block every federated call
// authenticates with (PROTOCOL §9).
func federatedSenderBody(id Identity, cert any) map[string]any {
	return map[string]any{
		"sender_account_id":   id.AccountID,
		"sender_root_pub_key": base64.StdEncoding.EncodeToString(id.RootPub),
		"sender_device_cert":  cert,
	}
}

// reportError turns the one server answer a caller has to distinguish into a
// sentinel, and leaves every other error alone.
func reportError(err error) error {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Code == "reports_disabled" {
		return ErrReportsUnavailable
	}
	return err
}

// ignoreNoSuchReport swallows the withdrawal of a report that is not there:
// the outcome being asked for is that no report of this user's stands, and it
// does not.
//
// Matched on the code and not on the status, which matters here more than it
// looks: "reports_disabled" is *also* a 404, and swallowing it would turn a
// server that never accepted the report into a withdrawal that appeared to
// work.
func ignoreNoSuchReport(err error) error {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound && apiErr.Code == "not_found" {
		return nil
	}
	return err
}
