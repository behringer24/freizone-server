-- A push subscription needs all three fields together: the endpoint URL
-- to POST to, and the recipient's ECDH public key (p256dh) + auth secret
-- used to RFC 8291-encrypt the payload for it. server_settings gets a
-- server-wide VAPID keypair (RFC 8292), generated once and reused for
-- every outgoing push -- see internal/store/settings.go.
ALTER TABLE devices ADD COLUMN push_endpoint TEXT;
ALTER TABLE devices ADD COLUMN push_p256dh TEXT;
ALTER TABLE devices ADD COLUMN push_auth TEXT;

ALTER TABLE server_settings ADD COLUMN vapid_public_key TEXT;
ALTER TABLE server_settings ADD COLUMN vapid_private_key TEXT;
