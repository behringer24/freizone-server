// Package config loads and validates server configuration from environment variables.
package config

import (
	"fmt"
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
	envPushGatewayURL       = "FREIZONE_PUSH_GATEWAY_URL"
	envFederationEnabled    = "FREIZONE_FEDERATION_ENABLED"
	envMaxRequestBodyBytes  = "FREIZONE_MAX_REQUEST_BODY_BYTES"
	envMaxQueuedMessages    = "FREIZONE_MAX_QUEUED_MESSAGES_PER_DEVICE"
)

const defaultMessageRetentionDays = 14

// defaultMaxRequestBodyBytes (512 KiB) is generous for a single E2E chat
// message (ciphertext + header, base64-encoded) while still bounding a
// request to a small, fixed cost regardless of who's sending it.
const defaultMaxRequestBodyBytes int64 = 512 * 1024

// defaultMaxQueuedMessagesPerDevice is deliberately generous -- far more
// than any real device should accumulate within the retention window --
// since this is a backstop against unbounded flooding, not a realistic
// usage cap.
const defaultMaxQueuedMessagesPerDevice = 1000

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

	if c.MaxRequestBodyBytes <= 0 {
		return fmt.Errorf("%s must be a positive number of bytes, got %d", envMaxRequestBodyBytes, c.MaxRequestBodyBytes)
	}

	if c.MaxQueuedMessagesPerDevice <= 0 {
		return fmt.Errorf("%s must be a positive number, got %d", envMaxQueuedMessages, c.MaxQueuedMessagesPerDevice)
	}

	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
