// Package config loads and validates server configuration from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
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

	// BlobsEnabled controls whether the encrypted blob transport
	// (internal/api/blobs.go, SRV-07) accepts uploads at all -- the same
	// kind of operator kill switch FederationEnabled is for federation.
	// Turning it off leaves existing blobs downloadable until they expire.
	BlobsEnabled bool

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

	// BlobRetentionDays is how long an unclaimed blob is kept. Defaults to
	// MessageRetentionDays and is validated not to be shorter, since a
	// blob must outlive the queued message that references it -- otherwise
	// a recipient who comes back late finds the message but not its image.
	BlobRetentionDays int
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
	envFederationEnabled    = "FREIZONE_FEDERATION_ENABLED"
	envMaxRequestBodyBytes  = "FREIZONE_MAX_REQUEST_BODY_BYTES"
	envMaxQueuedMessages    = "FREIZONE_MAX_QUEUED_MESSAGES_PER_DEVICE"
	envMaxBatchMessages     = "FREIZONE_MAX_BATCH_MESSAGES"
	envLogLevel             = "FREIZONE_LOG_LEVEL"

	envBlobsEnabled          = "FREIZONE_BLOBS_ENABLED"
	envBlobDir               = "FREIZONE_BLOB_DIR"
	envMaxBlobBytes          = "FREIZONE_MAX_BLOB_BYTES"
	envMaxBlobBytesPerDevice = "FREIZONE_MAX_BLOB_BYTES_PER_DEVICE"
	envMaxBlobsPerDevice     = "FREIZONE_MAX_BLOBS_PER_DEVICE"
	envBlobRetentionDays     = "FREIZONE_BLOB_RETENTION_DAYS"
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

	blobsEnabled := true
	if v := getenv(envBlobsEnabled); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value %q (must be true or false)", envBlobsEnabled, v)
		}
		blobsEnabled = parsed
	}
	cfg.BlobsEnabled = blobsEnabled

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

	if c.MaxRequestBodyBytes <= 0 {
		return fmt.Errorf("%s must be a positive number of bytes, got %d", envMaxRequestBodyBytes, c.MaxRequestBodyBytes)
	}

	if c.MaxQueuedMessagesPerDevice <= 0 {
		return fmt.Errorf("%s must be a positive number, got %d", envMaxQueuedMessages, c.MaxQueuedMessagesPerDevice)
	}

	if c.MaxBatchMessages <= 0 {
		return fmt.Errorf("%s must be a positive number, got %d", envMaxBatchMessages, c.MaxBatchMessages)
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

	if c.MaxBlobsPerDevice <= 0 {
		return fmt.Errorf("%s must be a positive number, got %d", envMaxBlobsPerDevice, c.MaxBlobsPerDevice)
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
