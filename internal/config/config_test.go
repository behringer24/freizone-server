package config

import "testing"

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(envMap(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.TLSMode != TLSModeOff {
		t.Errorf("TLSMode = %q, want %q", cfg.TLSMode, TLSModeOff)
	}
	if cfg.RegistrationPolicy != PolicyClosed {
		t.Errorf("RegistrationPolicy = %q, want %q", cfg.RegistrationPolicy, PolicyClosed)
	}
	if cfg.HTTPAddr != ":80" || cfg.HTTPSAddr != ":443" {
		t.Errorf("unexpected default addrs: http=%q https=%q", cfg.HTTPAddr, cfg.HTTPSAddr)
	}
	if cfg.DBPath != "data/freizone.db" && cfg.DBPath != "data\\freizone.db" {
		t.Errorf("unexpected default DBPath: %q", cfg.DBPath)
	}
	if cfg.MessageRetentionDays != defaultMessageRetentionDays {
		t.Errorf("MessageRetentionDays = %d, want %d", cfg.MessageRetentionDays, defaultMessageRetentionDays)
	}
}

func TestLoadInvalidTLSMode(t *testing.T) {
	_, err := Load(envMap(map[string]string{envTLSMode: "bogus"}))
	if err == nil {
		t.Fatal("expected error for invalid TLS mode")
	}
}

func TestLoadInvalidRegistrationPolicy(t *testing.T) {
	_, err := Load(envMap(map[string]string{envRegistrationPolicy: "bogus"}))
	if err == nil {
		t.Fatal("expected error for invalid registration policy")
	}
}

func TestLoadAutocertRequiresDomain(t *testing.T) {
	_, err := Load(envMap(map[string]string{envTLSMode: string(TLSModeAutocert)}))
	if err == nil {
		t.Fatal("expected error when autocert mode set without domain")
	}
}

func TestLoadAutocertWithDomain(t *testing.T) {
	cfg, err := Load(envMap(map[string]string{
		envTLSMode: string(TLSModeAutocert),
		envDomain:  "example.org",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Domain != "example.org" {
		t.Errorf("Domain = %q, want example.org", cfg.Domain)
	}
}

func TestLoadManualRequiresCertAndKey(t *testing.T) {
	_, err := Load(envMap(map[string]string{envTLSMode: string(TLSModeManual)}))
	if err == nil {
		t.Fatal("expected error when manual mode set without cert/key files")
	}

	cfg, err := Load(envMap(map[string]string{
		envTLSMode:     string(TLSModeManual),
		envTLSCertFile: "cert.pem",
		envTLSKeyFile:  "key.pem",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.TLSCertFile != "cert.pem" || cfg.TLSKeyFile != "key.pem" {
		t.Errorf("unexpected cert/key files: %q %q", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}

func TestLoadExplicitDBPath(t *testing.T) {
	cfg, err := Load(envMap(map[string]string{envDBPath: "/custom/path.db"}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DBPath != "/custom/path.db" {
		t.Errorf("DBPath = %q, want /custom/path.db", cfg.DBPath)
	}
}

func TestLoadExplicitMessageRetentionDays(t *testing.T) {
	cfg, err := Load(envMap(map[string]string{envMessageRetentionDays: "30"}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.MessageRetentionDays != 30 {
		t.Errorf("MessageRetentionDays = %d, want 30", cfg.MessageRetentionDays)
	}
}

func TestLoadRejectsNonNumericMessageRetentionDays(t *testing.T) {
	if _, err := Load(envMap(map[string]string{envMessageRetentionDays: "not-a-number"})); err == nil {
		t.Error("expected error for non-numeric message retention days")
	}
}

func TestLoadRejectsNonPositiveMessageRetentionDays(t *testing.T) {
	if _, err := Load(envMap(map[string]string{envMessageRetentionDays: "0"})); err == nil {
		t.Error("expected error for zero message retention days")
	}
	if _, err := Load(envMap(map[string]string{envMessageRetentionDays: "-5"})); err == nil {
		t.Error("expected error for negative message retention days")
	}
}
