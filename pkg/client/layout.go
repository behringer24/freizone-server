package client

// The on-disk layout, and why each piece has the shape it has.
//
//	<account>/
//	  format                       one line, names the layout
//	  identity.json                keys and per-account settings
//	  processed.log                handled message ids, append-only
//	  failures.json                decrypt-failure counts
//	  known.json                   peers that are not strangers
//	  blocked.json                 locally blocked peers
//	  prekeys/<id>.json            one file per unclaimed one-time prekey
//	  peers/<account-id>/
//	    session.json               the ratchet session sent on
//	    inbound.json               the read-only one, when there is one
//	    health.json                desync evidence, only when something is wrong
//	    profile.json               the name they assert, and the one we sent them
//	  chats/<chat-id>/
//	    meta.json                  conversation metadata
//	    log.jsonl                  the transcript, append-only
//
// Every choice above answers the same question: what does one incoming message
// cost?
//
//   - The transcript is a log, so a message costs one appended line whatever
//     the history behind it. Deletions and send-state changes are appended as
//     their own records rather than edited in place, because editing a line in
//     a text file means rewriting everything after it. Reading replays the log;
//     compaction happens on a threshold, never on the write path.
//   - A ratchet session advances on every message, so each one is its own file:
//     writing it rewrites a couple of kilobytes and touches no other peer.
//   - Conversation metadata changes per message too (last activity, unread),
//     and is one small file per chat for the same reason.
//   - Handled message ids change per message and are bounded, so they are held
//     in memory and appended to a log -- constant cost per message, with the
//     log compacted when it grows past twice the bound.
//   - Identity, prekeys, blocks and known peers change rarely. Whole-file
//     writes are fine there, and the files do not grow with history.
//
// Peers and chats are separate namespaces on purpose. They coincide for a
// one-to-one conversation, where the chat id is the peer's account id, and they
// do not for a group: a group chat has one transcript and as many peer sessions
// as it has members.

const (
	fileFormat    = "format"
	fileIdentity  = "identity.json"
	fileProcessed = "processed.log"
	fileFailures  = "failures.json"
	fileKnown     = "known.json"
	fileBlocked   = "blocked.json"
	fileSettings  = "settings.json"

	// filePending marks a registration that was started but not seen through.
	// Registration is not idempotent -- see register.go -- so the keys are on
	// disk before the request goes out, and this says the account behind them
	// may or may not exist yet.
	filePending = "registration.pending"

	dirPrekeys = "prekeys"
	dirPeers   = "peers"
	dirChats   = "chats"
	dirGroups  = "groups"

	// dirMedia is the default home for attachment bytes, and the only
	// directory here a caller may move elsewhere -- see Options.MediaPath.
	dirMedia = "media"

	// A group directory holds its facts, the events waiting on facts that have
	// not arrived, what each member last said their own view was, and the chat
	// state a list needs. The transcript is not here: a group chat is a chat,
	// and lives under dirChats keyed by group id like any other.
	fileFacts = "facts.json"
	fileHeld  = "held.json"
	filePeers = "peers.json"
	fileChat  = "chat.json"

	fileSession = "session.json"

	// fileDevice caches which device of a peer we talk to. Per peer rather than
	// on the conversation, because a group member is somebody we address without
	// necessarily having a one-to-one chat with them -- and minting one just to
	// hold a device id would put every group member in the chat list.
	fileDevice  = "device.json"
	fileInbound = "inbound.json"
	fileHealth  = "health.json"

	// fileProfile holds both directions of the profile name for one peer
	// (SRV-32): the claims they have made about themselves, verified, and the
	// timestamp of the last one we sent them about ourselves. One file rather
	// than two because they are read and written on the same paths.
	fileProfile = "profile.json"
	fileMeta    = "meta.json"
	fileLog     = "log.jsonl"
)

func (s *store) identityPath() (string, error)  { return s.path(fileIdentity) }
func (s *store) processedPath() (string, error) { return s.path(fileProcessed) }
func (s *store) failuresPath() (string, error)  { return s.path(fileFailures) }
func (s *store) knownPath() (string, error)     { return s.path(fileKnown) }
func (s *store) blockedPath() (string, error)   { return s.path(fileBlocked) }
func (s *store) settingsPath() (string, error)  { return s.path(fileSettings) }
func (s *store) pendingPath() (string, error)   { return s.path(filePending) }

func (s *store) prekeyPath(name string) (string, error) {
	return s.path(dirPrekeys, name)
}

func (s *store) peerPath(peer, name string) (string, error) {
	return s.path(dirPeers, peer, name)
}

func (s *store) chatPath(chatID, name string) (string, error) {
	return s.path(dirChats, chatID, name)
}

func (s *store) chatsDir() (string, error)  { return s.path(dirChats) }
func (s *store) groupsDir() (string, error) { return s.path(dirGroups) }

func (s *store) groupPath(groupID, name string) (string, error) {
	return s.path(dirGroups, groupID, name)
}
func (s *store) prekeysDir() (string, error) { return s.path(dirPrekeys) }
