-- relay_pubkey/relay_privkey are this server's own Ed25519 identity,
-- generated once and used to sign outgoing push-send requests to a
-- freizone-gateway instance (see internal/store/settings.go's
-- InitRelayIdentity, and internal/api/push.go's notifyPushViaGateway) --
-- the gateway verifies these self-describing signatures without any
-- prior registration, so no shared secret is provisioned here.
--
-- push_platform/push_target are the FCM/APNs counterpart to the
-- existing push_endpoint/push_p256dh/push_auth trio: a device uses
-- exactly one wake mechanism (UnifiedPush/Web Push, or an FCM/APNs
-- token relayed through a gateway) at a time -- see
-- SetDevicePushTarget's mutual exclusion with SetDevicePushSubscription.
ALTER TABLE server_settings ADD COLUMN relay_pubkey TEXT;
ALTER TABLE server_settings ADD COLUMN relay_privkey TEXT;

ALTER TABLE devices ADD COLUMN push_platform TEXT;
ALTER TABLE devices ADD COLUMN push_target TEXT;
