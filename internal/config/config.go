// Package config loads and validates server configuration from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TLSMode selects how the server terminates TLS.
type TLSMode string

const (
	TLSModeOff      TLSMode = "off"      // plain HTTP, for local development only
	TLSModeManual   TLSMode = "manual"   // operator-supplied cert/key files
	TLSModeAutocert TLSMode = "autocert" // automatic Let's Encrypt via ACME
)

// RegistrationPolicy controls whether new accounts may self-register.
type RegistrationPolicy string

const (
	PolicyOpen   RegistrationPolicy = "open"
	PolicyInvite RegistrationPolicy = "invite"
	PolicyClosed RegistrationPolicy = "closed"
)

// Config holds all server configuration.
type Config struct {
	Domain               string
	HTTPAddr             string
	HTTPSAddr            string
	TLSMode              TLSMode
	TLSCertFile          string
	TLSKeyFile           string
	DataDir              string
	DBPath               string
	RegistrationPolicy   RegistrationPolicy
	MessageRetentionDays int

	// InviteExpiryDays is how long a newly issued registration invite code
	// stays valid when the caller doesn't specify its own expiry. An
	// unbounded window is what makes guessing a code worth attempting at
	// all, so this defaults to a fixed period rather than "never". 0 means
	// no default expiry -- an explicit operator choice to go back to
	// codes that live until used.
	InviteExpiryDays int

	// LogLevel is the minimum severity written to the log ("debug",
	// "info", "warn", "error"; defaults to info). Mainly here so the
	// best-effort push paths -- whose individual failures are deliberately
	// logged at debug, since the durable queue is the real delivery
	// guarantee -- can be made visible while diagnosing a delivery
	// problem, without a rebuild.
	LogLevel slog.Level

	// PushGatewayURL is the base URL of a freizone-gateway instance this
	// server relays FCM/APNs push-wake requests to (see internal/api/
	// push.go's notifyPushViaGateway) -- empty disables that path
	// entirely, exactly like "no UnifiedPush distributor" already
	// degrades gracefully today. Any freizone-gateway works, whether
	// operated by this server's own operator or someone else's -- see
	// https://github.com/behringer24/freizone-gateway.
	PushGatewayURL string

	// PushCoalesceWindow collapses repeated wakes for the same device into
	// at most one per window (see internal/api/wakecoalesce.go). A wake
	// carries no content and no reason, so for a given device N of them in
	// quick succession say exactly what one says: go sync. A lively group
	// otherwise turns one burst of messages into one push per message per
	// member, which is the largest avoidable component of push load -- and,
	// on the device, of radio wake-ups.
	//
	// The first wake to an idle device is never delayed; only follow-up
	// wakes within the window are merged, into a single one at its end. 0
	// disables coalescing entirely, restoring one push per message.
	PushCoalesceWindow time.Duration

	// FederationEnabled controls whether POST /v1/federation/messages
	// (see internal/api/federation.go) accepts inbound cross-server
	// messages at all. Defaults to true (federation is open by design --
	// see docs/PROTOCOL.md); an operator who wants none of it can turn
	// the whole surface off without a code change.
	FederationEnabled bool

	// MaxRequestBodyBytes caps every incoming request body (applied as
	// middleware, internal/server/middleware.go's withMaxBody) -- without
	// this, a single request (e.g. a message payload) could be
	// arbitrarily large, limited only by host memory.
	MaxRequestBodyBytes int64

	// MaxQueuedMessagesPerDevice caps how many undelivered messages may
	// be queued for one recipient device at once (internal/store/
	// messages.go's CountPendingMessages, checked by handleSendMessage
	// and handleReceiveFederatedMessage before enqueuing another) --
	// without this, an unresponsive recipient (or, since federation
	// requires no registration, anyone who can mint a free Ed25519
	// identity) could flood a device's queue without bound.
	MaxQueuedMessagesPerDevice int

	// MaxBatchMessages caps how many messages one POST /v1/messages/batch
	// (or its federated twin) may carry. Batch delivery exists for group
	// fan-out (SRV-01): one request per distinct recipient server instead of
	// one per recipient device. The cap is a flood backstop in the same
	// spirit as MaxQueuedMessagesPerDevice -- MaxRequestBodyBytes already
	// bounds the bytes, this bounds the number of queue writes one request
	// can trigger. Advertised on GET /v1/server-status so a sender splits its
	// batches to fit rather than discovering the limit by being rejected.
	MaxBatchMessages int

	// MaxStreamsPerDevice caps how many concurrent SSE stream subscribers one
	// device may hold (internal/api/broker.go's subscribe, enforced by
	// handleMessageStream). Nothing bounded this before (SRV-28): the
	// subscriber map only ever grew, so a client with a reconnect bug
	// accumulated streams until the process ran out of file descriptors --
	// a ceiling inherited from whatever the Docker daemon defaults to rather
	// than a decision made here.
	//
	// Per device rather than server-wide, because that is where the runaway
	// actually happens and it is the only bound that cannot be tripped by
	// unrelated users: a server-wide cap turns one misbehaving client into an
	// outage for everybody, which is worse than the condition it prevents. A
	// handful is generous -- a device legitimately holds one, briefly two
	// across a reconnect that overlaps its predecessor.
	MaxStreamsPerDevice int

	// BlobsEnabled controls whether the encrypted blob transport
	// (internal/api/blobs.go, SRV-07) accepts uploads at all -- the same
	// kind of operator kill switch FederationEnabled is for federation.
	// Turning it off leaves existing blobs downloadable until they expire.
	BlobsEnabled bool

	// LandingPageEnabled controls whether GET / (internal/api/landing.go)
	// is registered at all (SRV-21). Unlike FederationEnabled/BlobsEnabled,
	// which change what their routes *return*, turning this off skips
	// registering the route in the first place -- a server run privately
	// gives the bare domain net/http's plain 404 rather than confirmation
	// that anything is running there, which a JSON "disabled" response
	// would still give away. Defaults to true: most operators are happy to
	// have Freizone explain itself at the root.
	LandingPageEnabled bool

	// ReportsEnabled controls whether this server accepts abuse reports
	// (internal/api/reports.go, SRV-33) -- the same operator kill switch shape
	// as FederationEnabled and BlobsEnabled, and discoverable the same way on
	// GET /v1/server-status, so a client can tell "switched off here" from
	// "too old to know about it". Defaults to true: a server whose operator
	// rarely looks is still a better home for a complaint than nowhere.
	ReportsEnabled bool

	// ReportRetentionDays is how long a report is kept, resolved or not. A
	// counter that never falls becomes a criminal record for something that
	// was never proven, and the evidence it carries goes with the row.
	ReportRetentionDays int

	// BlobDir is where blob ciphertext files live, defaulting to a "blobs"
	// subdirectory of DataDir. Deliberately the filesystem rather than a
	// SQLite column: the driver has no incremental blob I/O, so storing
	// them in the database would materialize whole files in memory on the
	// single-writer connection that also serves authentication.
	BlobDir string

	// MaxBlobBytes caps a single uploaded blob. This is what makes the
	// blob transport possible at all: MaxRequestBodyBytes is far too small
	// for a photo, so the blob routes carry their own, much larger limit
	// (see internal/server/middleware.go's per-path overrides). Separate
	// knob so raising it never widens the limit on every other route.
	MaxBlobBytes int64

	// MaxBlobBytesPerDevice and MaxBlobsPerDevice cap how much a single
	// recipient device may have stored at once. Both are needed because
	// the federated upload route, like federated messages, accepts uploads
	// from senders who never registered here -- without a quota that is an
	// unbounded disk-exhaustion surface.
	MaxBlobBytesPerDevice int64
	MaxBlobsPerDevice     int

	// MaxBlobBytesTotal caps the aggregate size of all stored blob ciphertext
	// on this server, a whole-disk backstop the per-device quotas cannot give:
	// those bound only what one recipient holds, so the real ceiling was
	// (#active devices) x MaxBlobBytesPerDevice, and the federated upload route
	// needs no local account at all. 0 (the default) disables it, preserving
	// prior behaviour; an operator on a small disk sets a real figure. Checked
	// before accepting an upload and re-checked inside the write transaction
	// (see internal/api/blobs.go), so it holds under concurrent uploads.
	MaxBlobBytesTotal int64

	// MaxBlobRecipients caps how many recipient devices one upload may name
	// (SRV-18), so a group picture costs one upload per recipient *server*
	// rather than one per member. A bound on the work a single request can
	// ask for, like MaxBatchMessages -- not a limit on group size, since a
	// sender may always split the recipients across several uploads.
	MaxBlobRecipients int

	// BlobRetentionDays is how long an unclaimed blob is kept. Defaults to
	// MessageRetentionDays and is validated not to be shorter, since a
	// blob must outlive the queued message that references it -- otherwise
	// a recipient who comes back late finds the message but not its image.
	BlobRetentionDays int

	// Attestation is an opaque, pkg/attest-encoded token an operator was
	// issued and pastes in here verbatim (see SRV-19). It is not a secret
	// -- it is served back on GET /v1/server-status exactly as given, and
	// clients verify it themselves against compiled-in issuer keys. Empty
	// means this server carries no attestation, which is the ordinary case
	// for the overwhelming majority of servers and is never treated as an
	// error.
	Attestation string
}

const (
	envDomain               = "FREIZONE_DOMAIN"
	envHTTPAddr             = "FREIZONE_HTTP_ADDR"
	envHTTPSAddr            = "FREIZONE_HTTPS_ADDR"
	envTLSMode              = "FREIZONE_TLS_MODE"
	envTLSCertFile          = "FREIZONE_TLS_CERT_FILE"
	envTLSKeyFile           = "FREIZONE_TLS_KEY_FILE"
	envDataDir              = "FREIZONE_DATA_DIR"
	envDBPath               = "FREIZONE_DB_PATH"
	envRegistrationPolicy   = "FREIZONE_REGISTRATION_POLICY"
	envMessageRetentionDays = "FREIZONE_MESSAGE_RETENTION_DAYS"
	envInviteExpiryDays     = "FREIZONE_INVITE_EXPIRY_DAYS"
	envPushGatewayURL       = "FREIZONE_PUSH_GATEWAY_URL"
	envPushCoalesceWindow   = "FREIZONE_PUSH_COALESCE_WINDOW"
	envFederationEnabled    = "FREIZONE_FEDERATION_ENABLED"
	envMaxRequestBodyBytes  = "FREIZONE_MAX_REQUEST_BODY_BYTES"
	envMaxQueuedMessages    = "FREIZONE_MAX_QUEUED_MESSAGES_PER_DEVICE"
	envMaxBatchMessages     = "FREIZONE_MAX_BATCH_MESSAGES"
	envMaxStreamsPerDevice  = "FREIZONE_MAX_STREAMS_PER_DEVICE"
	envLogLevel             = "FREIZONE_LOG_LEVEL"

	envBlobsEnabled          = "FREIZONE_BLOBS_ENABLED"
	envReportsEnabled        = "FREIZONE_REPORTS_ENABLED"
	envReportRetentionDays   = "FREIZONE_REPORT_RETENTION_DAYS"
	envBlobDir               = "FREIZONE_BLOB_DIR"
	envMaxBlobBytes          = "FREIZONE_MAX_BLOB_BYTES"
	envMaxBlobBytesPerDevice = "FREIZONE_MAX_BLOB_BYTES_PER_DEVICE"
	envMaxBlobsPerDevice     = "FREIZONE_MAX_BLOBS_PER_DEVICE"
	envMaxBlobBytesTotal     = "FREIZONE_MAX_BLOB_BYTES_TOTAL"
	envMaxBlobRecipients     = "FREIZONE_MAX_BLOB_RECIPIENTS"
	envBlobRetentionDays     = "FREIZONE_BLOB_RETENTION_DAYS"

	envLandingPageEnabled = "FREIZONE_LANDING_PAGE_ENABLED"

	envAttestation = "FREIZONE_ATTESTATION"
)

const defaultMessageRetentionDays = 14

// defaultInviteExpiryDays bounds how long an unredeemed invite code stays
// guessable. Two weeks is long enough to hand someone a code out of band and
// have them get around to it, short enough that a code left lying around
// stops mattering.
const defaultInviteExpiryDays = 14

// defaultMaxRequestBodyBytes (512 KiB) is generous for a single E2E chat
// message (ciphertext + header, base64-encoded) while still bounding a
// request to a small, fixed cost regardless of who's sending it.
const defaultMaxRequestBodyBytes int64 = 512 * 1024

// defaultMaxQueuedMessagesPerDevice is deliberately generous -- far more
// than any real device should accumulate within the retention window --
// since this is a backstop against unbounded flooding, not a realistic
// usage cap.
const defaultMaxQueuedMessagesPerDevice = 1000

// defaultMaxBatchMessages (100) is well above the group size pairwise fan-out
// is designed for (~50 members, see docs/design/01-groups.md) even with
// several devices each, while keeping one request's worth of queue writes
// bounded. A sender that needs more splits the batch, which it must be able
// to do anyway to stay under MaxRequestBodyBytes.
const defaultMaxBatchMessages = 100

// defaultMaxStreamsPerDevice (4) is well above legitimate use and well below
// anything that costs the process something. One device holds one stream;
// two briefly, when a reconnect overlaps the connection it replaces and the
// old one has not yet noticed it is gone. Four leaves room for that to happen
// twice over before anything is refused.
const defaultMaxStreamsPerDevice = 4

// defaultReportRetentionDays is a quarter: long enough that a pattern across
// several complaints is still visible, short enough that a single incident
// does not follow somebody around indefinitely.
const defaultReportRetentionDays = 90

// defaultMaxBlobBytes (8 MiB) comfortably fits a client-compressed photo
// (clients downscale to roughly 1600px before uploading, landing well under
// 1 MiB) with room for the occasional larger one, without inviting arbitrary
// file hosting.
const defaultMaxBlobBytes int64 = 8 * 1024 * 1024

// defaultMaxBlobBytesPerDevice / defaultMaxBlobsPerDevice bound what one
// recipient device can hold at once -- the blob counterpart to
// defaultMaxQueuedMessagesPerDevice, and likewise a flood backstop rather
// than an expected usage level.
const (
	defaultMaxBlobBytesPerDevice int64 = 128 * 1024 * 1024
	defaultMaxBlobsPerDevice           = 200
)

// defaultMaxBlobRecipients matches defaultMaxBatchMessages deliberately: the
// recipients of one upload are the members whose message copies that same
// fan-out then batches to that same server, so two different bounds would
// only ever be confusing.
const defaultMaxBlobRecipients = defaultMaxBatchMessages

// defaultPushCoalesceWindow is short enough that a follow-up notification
// still feels immediate to someone already looking at the device, and long
// enough to collapse the burst a lively group produces. The wake that
// actually competes for attention -- the first one, to an idle device -- is
// never delayed by it, so the trade-off is one-sided in its favour.
const defaultPushCoalesceWindow = 3 * time.Second

// maxPushCoalesceWindow is a footgun bound rather than a technical one.
// time.ParseDuration accepts "3m" as readily as "3s", and the difference
// between them is a three-minute notification delay that nothing in the
// system reports as wrong -- messages still arrive, just late enough to look
// like push is broken.
const maxPushCoalesceWindow = time.Minute

// Load reads configuration from the process environment.
func Load(getenv func(string) string) (*Config, error) {
	cfg := &Config{
		Domain:             getenv(envDomain),
		HTTPAddr:           orDefault(getenv(envHTTPAddr), ":80"),
		HTTPSAddr:          orDefault(getenv(envHTTPSAddr), ":443"),
		TLSMode:            TLSMode(orDefault(getenv(envTLSMode), string(TLSModeOff))),
		TLSCertFile:        getenv(envTLSCertFile),
		TLSKeyFile:         getenv(envTLSKeyFile),
		DataDir:            orDefault(getenv(envDataDir), "./data"),
		RegistrationPolicy: RegistrationPolicy(orDefault(getenv(envRegistrationPolicy), string(PolicyClosed))),
		PushGatewayURL:     strings.TrimSuffix(getenv(envPushGatewayURL), "/"),
		// Not validated here: a malformed or expired token is an operator's
		// problem to notice and fix, never a reason this server refuses to
		// start -- see main.go's startup check, which only warns.
		Attestation: strings.TrimSpace(getenv(envAttestation)),
	}

	dbPath := getenv(envDBPath)
	if dbPath == "" {
		dbPath = filepath.Join(cfg.DataDir, "freizone.db")
	}
	cfg.DBPath = dbPath

	retentionDays := defaultMessageRetentionDays
	if v := getenv(envMessageRetentionDays); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number of days): %w", envMessageRetentionDays, v, err)
		}
		retentionDays = parsed
	}
	cfg.MessageRetentionDays = retentionDays

	inviteExpiryDays := defaultInviteExpiryDays
	if v := getenv(envInviteExpiryDays); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number of days): %w", envInviteExpiryDays, v, err)
		}
		inviteExpiryDays = parsed
	}
	cfg.InviteExpiryDays = inviteExpiryDays

	coalesceWindow := defaultPushCoalesceWindow
	if v := getenv(envPushCoalesceWindow); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a duration such as 3s or 500ms): %w", envPushCoalesceWindow, v, err)
		}
		coalesceWindow = parsed
	}
	cfg.PushCoalesceWindow = coalesceWindow

	logLevel, err := parseLogLevel(getenv(envLogLevel))
	if err != nil {
		return nil, err
	}
	cfg.LogLevel = logLevel

	federationEnabled := true
	if v := getenv(envFederationEnabled); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be true or false)", envFederationEnabled, v)
		}
		federationEnabled = parsed
	}
	cfg.FederationEnabled = federationEnabled

	maxBodyBytes := defaultMaxRequestBodyBytes
	if v := getenv(envMaxRequestBodyBytes); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number of bytes): %w", envMaxRequestBodyBytes, v, err)
		}
		maxBodyBytes = parsed
	}
	cfg.MaxRequestBodyBytes = maxBodyBytes

	maxQueuedMessages := defaultMaxQueuedMessagesPerDevice
	if v := getenv(envMaxQueuedMessages); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number): %w", envMaxQueuedMessages, v, err)
		}
		maxQueuedMessages = parsed
	}
	cfg.MaxQueuedMessagesPerDevice = maxQueuedMessages

	maxBatchMessages := defaultMaxBatchMessages
	if v := getenv(envMaxBatchMessages); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number): %w", envMaxBatchMessages, v, err)
		}
		maxBatchMessages = parsed
	}
	cfg.MaxBatchMessages = maxBatchMessages

	maxStreamsPerDevice := defaultMaxStreamsPerDevice
	if v := getenv(envMaxStreamsPerDevice); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number): %w", envMaxStreamsPerDevice, v, err)
		}
		maxStreamsPerDevice = parsed
	}
	cfg.MaxStreamsPerDevice = maxStreamsPerDevice

	blobsEnabled := true
	if v := getenv(envBlobsEnabled); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be true or false)", envBlobsEnabled, v)
		}
		blobsEnabled = parsed
	}
	cfg.BlobsEnabled = blobsEnabled

	reportsEnabled := true
	if v := getenv(envReportsEnabled); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be true or false)", envReportsEnabled, v)
		}
		reportsEnabled = parsed
	}
	cfg.ReportsEnabled = reportsEnabled

	reportRetentionDays := defaultReportRetentionDays
	if v := getenv(envReportRetentionDays); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed < 1 {
			return nil, fmt.Errorf("%s: invalid value %q (must be a positive number of days)", envReportRetentionDays, v)
		}
		reportRetentionDays = parsed
	}
	cfg.ReportRetentionDays = reportRetentionDays

	blobDir := getenv(envBlobDir)
	if blobDir == "" {
		blobDir = filepath.Join(cfg.DataDir, "blobs")
	}
	cfg.BlobDir = blobDir

	maxBlobBytes := defaultMaxBlobBytes
	if v := getenv(envMaxBlobBytes); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number of bytes): %w", envMaxBlobBytes, v, err)
		}
		maxBlobBytes = parsed
	}
	cfg.MaxBlobBytes = maxBlobBytes

	maxBlobBytesPerDevice := defaultMaxBlobBytesPerDevice
	if v := getenv(envMaxBlobBytesPerDevice); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number of bytes): %w", envMaxBlobBytesPerDevice, v, err)
		}
		maxBlobBytesPerDevice = parsed
	}
	cfg.MaxBlobBytesPerDevice = maxBlobBytesPerDevice

	maxBlobsPerDevice := defaultMaxBlobsPerDevice
	if v := getenv(envMaxBlobsPerDevice); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number): %w", envMaxBlobsPerDevice, v, err)
		}
		maxBlobsPerDevice = parsed
	}
	cfg.MaxBlobsPerDevice = maxBlobsPerDevice

	// Unset means 0, which disables the aggregate cap (the prior behaviour).
	var maxBlobBytesTotal int64
	if v := getenv(envMaxBlobBytesTotal); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number of bytes): %w", envMaxBlobBytesTotal, v, err)
		}
		maxBlobBytesTotal = parsed
	}
	cfg.MaxBlobBytesTotal = maxBlobBytesTotal

	maxBlobRecipients := defaultMaxBlobRecipients
	if v := getenv(envMaxBlobRecipients); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number): %w", envMaxBlobRecipients, v, err)
		}
		maxBlobRecipients = parsed
	}
	cfg.MaxBlobRecipients = maxBlobRecipients

	// Defaults to the message retention window: a blob exists to be fetched
	// by the message that references it, so the two lifetimes belong together.
	blobRetentionDays := cfg.MessageRetentionDays
	if v := getenv(envBlobRetentionDays); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be a whole number of days): %w", envBlobRetentionDays, v, err)
		}
		blobRetentionDays = parsed
	}
	cfg.BlobRetentionDays = blobRetentionDays

	landingPageEnabled := true
	if v := getenv(envLandingPageEnabled); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be true or false)", envLandingPageEnabled, v)
		}
		landingPageEnabled = parsed
	}
	cfg.LandingPageEnabled = landingPageEnabled

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	switch c.TLSMode {
	case TLSModeOff, TLSModeManual, TLSModeAutocert:
	default:
		return fmt.Errorf("%s: invalid value %q (must be one of off, manual, autocert)", envTLSMode, c.TLSMode)
	}

	switch c.RegistrationPolicy {
	case PolicyOpen, PolicyInvite, PolicyClosed:
	default:
		return fmt.Errorf("%s: invalid value %q (must be one of open, invite, closed)", envRegistrationPolicy, c.RegistrationPolicy)
	}

	if c.TLSMode == TLSModeAutocert && c.Domain == "" {
		return fmt.Errorf("%s is required when %s=%s", envDomain, envTLSMode, TLSModeAutocert)
	}

	if c.TLSMode == TLSModeManual && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		return fmt.Errorf("%s and %s are required when %s=%s", envTLSCertFile, envTLSKeyFile, envTLSMode, TLSModeManual)
	}

	if c.MessageRetentionDays <= 0 {
		return fmt.Errorf("%s must be a positive number of days, got %d", envMessageRetentionDays, c.MessageRetentionDays)
	}

	// 0 is meaningful here (no default expiry), so only negatives are wrong.
	if c.InviteExpiryDays < 0 {
		return fmt.Errorf("%s must not be negative, got %d", envInviteExpiryDays, c.InviteExpiryDays)
	}

	// 0 is meaningful here too (coalescing off), so only negatives are wrong.
	if c.PushCoalesceWindow < 0 {
		return fmt.Errorf("%s must not be negative, got %s", envPushCoalesceWindow, c.PushCoalesceWindow)
	}
	if c.PushCoalesceWindow > maxPushCoalesceWindow {
		return fmt.Errorf("%s (%s) must not exceed %s -- beyond that a device's follow-up notifications are delayed far enough to look like push is broken; set 0 to disable coalescing instead",
			envPushCoalesceWindow, c.PushCoalesceWindow, maxPushCoalesceWindow)
	}

	if c.MaxRequestBodyBytes <= 0 {
		return fmt.Errorf("%s must be a positive number of bytes, got %d", envMaxRequestBodyBytes, c.MaxRequestBodyBytes)
	}

	if c.MaxQueuedMessagesPerDevice <= 0 {
		return fmt.Errorf("%s must be a positive number, got %d", envMaxQueuedMessages, c.MaxQueuedMessagesPerDevice)
	}

	if c.MaxBatchMessages <= 0 {
		return fmt.Errorf("%s must be a positive number, got %d", envMaxBatchMessages, c.MaxBatchMessages)
	}

	if c.MaxStreamsPerDevice <= 0 {
		return fmt.Errorf("%s must be a positive number, got %d", envMaxStreamsPerDevice, c.MaxStreamsPerDevice)
	}

	if c.MaxBlobBytes <= 0 {
		return fmt.Errorf("%s must be a positive number of bytes, got %d", envMaxBlobBytes, c.MaxBlobBytes)
	}

	if c.MaxBlobBytesPerDevice <= 0 {
		return fmt.Errorf("%s must be a positive number of bytes, got %d", envMaxBlobBytesPerDevice, c.MaxBlobBytesPerDevice)
	}

	// A per-device quota below the single-blob limit would reject every
	// upload at that size -- an operator raising one and not the other would
	// otherwise get a server that silently accepts nothing.
	if c.MaxBlobBytesPerDevice < c.MaxBlobBytes {
		return fmt.Errorf("%s (%d) must be at least %s (%d), otherwise no blob of the maximum size could ever be stored",
			envMaxBlobBytesPerDevice, c.MaxBlobBytesPerDevice, envMaxBlobBytes, c.MaxBlobBytes)
	}

	if c.MaxBlobRecipients <= 0 {
		return fmt.Errorf("%s must be a positive number, got %d", envMaxBlobRecipients, c.MaxBlobRecipients)
	}

	if c.MaxBlobsPerDevice <= 0 {
		return fmt.Errorf("%s must be a positive number, got %d", envMaxBlobsPerDevice, c.MaxBlobsPerDevice)
	}

	// 0 means "no aggregate cap", so only negatives are wrong. A positive cap
	// below the single-blob limit could never store even one blob -- the same
	// footgun the per-device check above guards against.
	if c.MaxBlobBytesTotal < 0 {
		return fmt.Errorf("%s must not be negative, got %d", envMaxBlobBytesTotal, c.MaxBlobBytesTotal)
	}
	if c.MaxBlobBytesTotal > 0 && c.MaxBlobBytesTotal < c.MaxBlobBytes {
		return fmt.Errorf("%s (%d) must be at least %s (%d), otherwise no blob of the maximum size could ever be stored",
			envMaxBlobBytesTotal, c.MaxBlobBytesTotal, envMaxBlobBytes, c.MaxBlobBytes)
	}

	if c.BlobRetentionDays <= 0 {
		return fmt.Errorf("%s must be a positive number of days, got %d", envBlobRetentionDays, c.BlobRetentionDays)
	}

	// A blob has to outlive the message pointing at it: the recipient learns
	// the blob id only by decrypting that message, so expiring blobs sooner
	// would leave retrievable messages referencing images that are already gone.
	if c.BlobRetentionDays < c.MessageRetentionDays {
		return fmt.Errorf("%s (%d) must not be shorter than %s (%d), or a message could outlive the blob it references",
			envBlobRetentionDays, c.BlobRetentionDays, envMessageRetentionDays, c.MessageRetentionDays)
	}

	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// parseLogLevel maps the level names an operator would reasonably type
// (case-insensitively) onto slog levels, defaulting to info when unset.
func parseLogLevel(v string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("%s: invalid value %q (must be one of: debug, info, warn, error)", envLogLevel, v)
	}
}
