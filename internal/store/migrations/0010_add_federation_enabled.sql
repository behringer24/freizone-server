-- federation_enabled makes the inbound-federation switch a runtime,
-- admin-settable server setting (like registration_policy) instead of a
-- static env-only flag. Nullable with no default, seeded on first boot from
-- FREIZONE_FEDERATION_ENABLED by store.InitFederationEnabled -- the same
-- "env seeds once, DB is authoritative thereafter" pattern the VAPID and
-- relay-identity columns use. Stored as 0/1 (SQLite has no boolean).
ALTER TABLE server_settings ADD COLUMN federation_enabled INTEGER;
