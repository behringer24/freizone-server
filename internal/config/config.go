// Package config loads and validates server configuration from environment variables.
package config

import (
	"fmt"
	"path/filepath"
	"strconv"
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
)

const defaultMessageRetentionDays = 14

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

	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
