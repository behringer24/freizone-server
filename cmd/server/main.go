// Command server runs the Freizone server.
package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/behringer24/freizone-server/internal/api"
	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/blobstore"
	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/logging"
	"github.com/behringer24/freizone-server/internal/server"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/attest"
)

const (
	nonceCleanupInterval = 10 * time.Minute

	// wakeStateCleanupInterval drops push-coalescing state for devices that
	// have gone quiet. Unhurried on purpose: the map holds one small entry
	// per device woken since start, not one per request, so this is
	// housekeeping rather than a bound that has to hold.
	wakeStateCleanupInterval = 30 * time.Minute
	messageCleanupInterval   = 1 * time.Hour
	// inviteCleanupInterval is generous on purpose: invite expiry is measured
	// in days, and nothing depends on an expired code disappearing promptly
	// -- it is already unusable the moment it expires. This only reclaims the
	// row.
	inviteCleanupInterval = 6 * time.Hour

	blobCleanupInterval = 1 * time.Hour
	// blobCleanupBatchSize bounds one expiry pass: each blob costs a file
	// unlink, so a large backlog is worked off over several ticks instead of
	// blocking one of them for a long time.
	blobCleanupBatchSize = 500
	// blobTmpMaxAge is how long a partially-written upload may sit before it
	// counts as abandoned. Comfortably longer than any real upload.
	blobTmpMaxAge = 1 * time.Hour
	// blobOrphanSweepInterval throttles the full directory walk that finds
	// files with no metadata row -- orphans only arise from a crash, so this
	// need not run every tick.
	blobOrphanSweepInterval = 24 * time.Hour

	// statsSnapshotInterval is how often a server-stats history point is
	// recorded for the admin statistics page's growth charts. Four a day
	// (every six hours) resolves same-day load spikes without generating
	// more rows than the point of a long-range trend chart justifies.
	statsSnapshotInterval = 6 * time.Hour
	// statsSnapshotRetention bounds the stats_snapshots table -- unlike
	// every other cleanup ticker here, nothing else ever deletes from it, so
	// without a retention window it would grow forever. Two years gives the
	// admin page a long runway to look back on (at 4/day that is still only
	// ~2900 rows, trivial for SQLite) even right before the oldest point
	// ages out.
	statsSnapshotRetention = 2 * 365 * 24 * time.Hour
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	resetSetupToken := flag.Bool("reset-setup-token", false, "delete any existing (possibly lost or already-claimed) setup token, forcing a fresh one to be generated on this start")
	resetAdmin := flag.Bool("reset-admin", false, "recover a lost admin (device/root key gone): does the exact same thing as --reset-setup-token, under a name for this specific scenario -- claiming with the fresh token creates an additional/replacement admin, it does not remove the old one")
	flag.Parse()

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	logger := logging.New(os.Stdout, logging.FormatJSON, cfg.LogLevel)

	checkAttestation(cfg, logger)

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	if err := store.Migrate(db); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	if *resetSetupToken {
		if err := store.ResetSetupToken(db); err != nil {
			return fmt.Errorf("resetting setup token: %w", err)
		}
		logger.Info("setup token reset; a fresh one will be generated")
	}
	if *resetAdmin {
		if err := store.ResetSetupToken(db); err != nil {
			return fmt.Errorf("resetting admin: %w", err)
		}
		logger.Info("admin reset requested; a fresh setup token will be generated to claim a replacement or additional admin")
	}

	if err := store.InitRegistrationPolicy(db, string(cfg.RegistrationPolicy)); err != nil {
		return fmt.Errorf("initializing registration policy: %w", err)
	}

	// Seeds the runtime federation flag from the env var on first boot; the DB
	// value is authoritative thereafter (admin-settable via /v1/admin/federation).
	if err := store.InitFederationEnabled(db, cfg.FederationEnabled); err != nil {
		return fmt.Errorf("initializing federation setting: %w", err)
	}

	if err := store.InitVAPIDKeys(db); err != nil {
		return fmt.Errorf("initializing vapid keys: %w", err)
	}
	vapidPublicKey, vapidPrivateKey, err := store.GetVAPIDKeys(db)
	if err != nil {
		return fmt.Errorf("loading vapid keys: %w", err)
	}

	if err := store.InitRelayIdentity(db); err != nil {
		return fmt.Errorf("initializing relay identity: %w", err)
	}
	relayPub, relayPriv, err := store.GetRelayIdentity(db)
	if err != nil {
		return fmt.Errorf("loading relay identity: %w", err)
	}
	// Not a secret -- this is exactly what any freizone-gateway sees in
	// Signature-Key-Id on every relayed request, so an operator who ever
	// needs to identify or discuss this server with a gateway operator
	// (e.g. "please don't revoke me") can find it in their own logs.
	logger.Info("relay identity ready", "public_key", base64.StdEncoding.EncodeToString(relayPub))

	if err := printSetupTokenIfNew(db, logger); err != nil {
		return fmt.Errorf("initializing setup token: %w", err)
	}

	authMW := auth.NewMiddleware(db, logger)
	// The blob upload's body is ciphertext streamed straight to disk, so its
	// signature is checked against the client's stated digest rather than by
	// buffering the body. Scoped to this one route prefix -- see
	// auth.Middleware.StreamedBodyPaths for why it must not be general.
	authMW.StreamedBodyPaths = []string{"POST /v1/blobs"}

	a := api.New(db, cfg, authMW, logger)
	a.VAPIDPublicKey = vapidPublicKey
	a.VAPIDPrivateKey = vapidPrivateKey
	a.RelayPubKey = relayPub
	a.RelayPrivKey = relayPriv

	blobs, err := blobstore.New(cfg.BlobDir)
	if err != nil {
		return fmt.Errorf("initializing blob store: %w", err)
	}
	a.Blobs = blobs

	handler := a.Router()

	srv, err := server.New(server.Options{
		Domain:              cfg.Domain,
		HTTPAddr:            cfg.HTTPAddr,
		HTTPSAddr:           cfg.HTTPSAddr,
		TLSMode:             cfg.TLSMode,
		TLSCertFile:         cfg.TLSCertFile,
		TLSKeyFile:          cfg.TLSKeyFile,
		AutocertCacheDir:    filepath.Join(cfg.DataDir, "autocert-cache"),
		Handler:             handler,
		Logger:              logger,
		MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
		// The blob routes carry image ciphertext, orders of magnitude larger
		// than a chat message -- and the cap is applied outside the handler,
		// so the exception has to be declared here rather than in the handler.
		BodyLimitOverrides: []server.BodyLimitOverride{
			{PathPrefix: "/v1/blobs", MaxBytes: cfg.MaxBlobBytes},
			{PathPrefix: "/v1/federation/blobs", MaxBytes: cfg.MaxBlobBytes},
		},
	})
	if err != nil {
		return fmt.Errorf("configuring server: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	nonceCleanupDone := runNonceCleanup(ctx, authMW, logger)
	messageCleanupDone := runMessageCleanup(ctx, db, logger)
	blobCleanupDone := runBlobCleanup(ctx, db, blobs, logger)
	inviteCleanupDone := runInviteCleanup(ctx, db, logger)
	statsSnapshotDone := runStatsSnapshot(ctx, a, logger)
	wakeStateCleanupDone := runWakeStateCleanup(ctx, a)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	logger.Info("server started", "tls_mode", string(cfg.TLSMode), "http_addr", cfg.HTTPAddr, "https_addr", cfg.HTTPSAddr)

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down server: %w", err)
	}

	// After the listener has stopped, so nothing new can arrive: emit any
	// wake still held inside a coalescing window. Losing one here would look
	// exactly like push being broken to whoever was mid-conversation, and it
	// costs a few requests to avoid.
	a.FlushPendingWakes()

	<-nonceCleanupDone
	<-messageCleanupDone
	<-blobCleanupDone
	<-inviteCleanupDone
	<-statsSnapshotDone
	<-wakeStateCleanupDone
	return nil
}

// runWakeStateCleanup periodically drops push-coalescing state for devices
// whose window has closed with nothing pending.
func runWakeStateCleanup(ctx context.Context, a *api.API) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(wakeStateCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.EvictIdleWakeState()
			}
		}
	}()
	return done
}

// checkAttestation reports whether this server's configured attestation
// (SRV-19, FREIZONE_ATTESTATION) is genuine and current -- purely for
// operator visibility. A missing, malformed, foreign-domain or expired
// attestation only ever logs a warning here and never stops the server from
// starting or serving chat: the badge this eventually produces is additive
// (see docs/design/19-attested-servers.md), and turning a cosmetic
// credential into an outage would defeat that on the spot.
func checkAttestation(cfg *config.Config, logger *slog.Logger) {
	if cfg.Attestation == "" {
		return
	}

	a, err := attest.Decode(cfg.Attestation)
	if err != nil {
		logger.Warn("configured attestation is malformed", "error", err)
		return
	}

	if len(attest.TrustedIssuers) == 0 {
		logger.Warn("attestation configured, but this build has no trusted issuer keys compiled in -- it will be served on GET /v1/server-status as configured, but this server cannot itself confirm it is genuine")
		return
	}

	if err := a.Verify(attest.TrustedIssuers); err != nil {
		logger.Warn("configured attestation failed verification", "error", err)
		return
	}

	if cfg.Domain == "" {
		// Common and legitimate, not a misconfiguration: FREIZONE_DOMAIN is
		// only required in autocert mode (see config.go) -- a server behind
		// an external reverse proxy that terminates TLS itself (nginx-proxy
		// + acme-companion, Caddy, Traefik, ...) has no reason to be told
		// its own public domain at all. This server genuinely cannot check
		// the attestation is for the domain it is reached at in that case
		// -- a real client does that check itself against the domain it
		// actually connected to (pkg/attest.Valid) -- so this only confirms
		// the signature and stops short of a domain/expiry check it cannot
		// meaningfully perform. Info, not Warn: nothing here is wrong.
		logger.Info("attestation is genuinely signed, but FREIZONE_DOMAIN is unset so this server cannot itself confirm which domain it is for", "tier", a.Tier, "subject", a.Subject)
		return
	}

	if err := a.Valid(cfg.Domain, time.Now()); err != nil {
		logger.Warn("configured attestation is not currently valid", "error", err)
		return
	}

	logger.Info("attestation verified", "tier", a.Tier, "subject", a.Subject, "expires_at", a.ExpiresAt.UTC().Format(time.RFC3339))
}

// printSetupTokenIfNew generates the one-time bootstrap setup token on the
// very first run and prints it prominently -- this is the only time its
// plaintext is ever available (only its hash is stored).
func printSetupTokenIfNew(db *sql.DB, logger *slog.Logger) error {
	token, created, err := store.InitSetupToken(db, time.Now())
	if err != nil {
		return err
	}
	if !created {
		logger.Info("setup token already initialized (use --reset-setup-token to regenerate if it was lost before being claimed)")
		return nil
	}

	fmt.Println("================================================================")
	fmt.Println(" Freizone setup token (save this now -- it will not be shown again):")
	fmt.Println()
	fmt.Println(" " + formatSetupTokenForDisplay(token))
	fmt.Println()
	fmt.Println(" Use it to claim the first admin account via POST /v1/bootstrap/claim.")
	fmt.Println(" (Dashes are cosmetic -- enter it with or without them.)")
	fmt.Println("================================================================")
	return nil
}

// formatSetupTokenForDisplay inserts a hyphen halfway through the token for
// readability (e.g. "ABCD-1234"). Purely cosmetic: store.ClaimSetupToken
// normalizes separators/case away before comparing.
func formatSetupTokenForDisplay(token string) string {
	mid := len(token) / 2
	return token[:mid] + "-" + token[mid:]
}

// runNonceCleanup starts a background goroutine that periodically purges
// expired signature-replay nonces, until ctx is cancelled. It purges both the
// middleware's in-memory cache (device-signed requests) AND the persistent
// used_nonces table (the public root-key-signed recovery and federation
// endpoints record their nonces there, since those handlers run outside the
// middleware -- see internal/api/recover.go and federation.go). Without the
// DB purge that table would grow without bound. The returned channel is closed
// once the goroutine has exited.
func runNonceCleanup(ctx context.Context, authMW *auth.Middleware, logger *slog.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(nonceCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				if n := authMW.PurgeExpiredNonces(now); n > 0 {
					logger.Info("purged expired nonces", "count", n)
				}
				if n, err := store.PurgeExpiredNonces(authMW.DB, now); err != nil {
					logger.Warn("purging persistent nonces failed", "error", err)
				} else if n > 0 {
					logger.Info("purged expired persistent nonces", "count", n)
				}
			}
		}
	}()
	return done
}

// runBlobCleanup starts a background goroutine that periodically expires
// stored blobs, until ctx is cancelled. The returned channel is closed once
// the goroutine has exited.
//
// Four jobs, all bounded per tick so a large backlog is worked off across
// several rounds rather than in one long stall:
//   - expired blobs: file unlinked, then the row dropped.
//   - unreferenced blobs: the last recipient's claim went with a removed
//     device, so nothing can fetch them any more (SRV-18).
//   - leftover temp files from uploads that died mid-write.
//   - orphan files whose row is gone (the crash window between writing the
//     file and inserting the row, or a delete that failed after the row).
func runBlobCleanup(ctx context.Context, db *sql.DB, blobs *blobstore.Store, logger *slog.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(blobCleanupInterval)
		defer ticker.Stop()
		var sinceOrphanSweep time.Duration
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()

				expired, err := store.ListExpiredBlobs(db, now, blobCleanupBatchSize)
				if err != nil {
					logger.Warn("blob cleanup failed", "error", err)
				} else {
					removed := 0
					for _, b := range expired {
						// File first: a failure here leaves a row we will
						// retry next tick, whereas dropping the row first
						// would strand the file with nothing pointing at it.
						if err := blobs.Remove(b.BlobID); err != nil {
							logger.Warn("removing expired blob file failed", "error", err, "blob_id", b.BlobID)
							continue
						}
						if err := store.DeleteBlobByID(db, b.BlobID); err != nil {
							logger.Warn("removing expired blob row failed", "error", err, "blob_id", b.BlobID)
							continue
						}
						removed++
					}
					if removed > 0 {
						logger.Info("purged expired blobs", "count", removed)
					}
				}

				// Blobs nobody claims any more. The ordinary DELETE path
				// retires those immediately; this catches the ones a device
				// removal orphaned, where the cascade drops the last
				// recipient row without noticing what it left behind.
				unreferenced, err := store.ListUnreferencedBlobs(db, blobCleanupBatchSize)
				if err != nil {
					logger.Warn("listing unreferenced blobs failed", "error", err)
				} else {
					removed := 0
					for _, b := range unreferenced {
						if err := blobs.Remove(b.BlobID); err != nil {
							logger.Warn("removing unreferenced blob file failed", "error", err, "blob_id", b.BlobID)
							continue
						}
						if err := store.DeleteBlobByID(db, b.BlobID); err != nil {
							logger.Warn("removing unreferenced blob row failed", "error", err, "blob_id", b.BlobID)
							continue
						}
						removed++
					}
					if removed > 0 {
						logger.Info("purged unreferenced blobs", "count", removed)
					}
				}

				if n, err := blobs.SweepTmp(blobTmpMaxAge, now); err != nil {
					logger.Warn("sweeping blob temp files failed", "error", err)
				} else if n > 0 {
					logger.Info("swept abandoned blob uploads", "count", n)
				}

				// Far rarer than the expiry pass: it walks the whole blob
				// directory, and orphans only appear after a crash.
				sinceOrphanSweep += blobCleanupInterval
				if sinceOrphanSweep >= blobOrphanSweepInterval {
					sinceOrphanSweep = 0
					if n, err := sweepOrphanBlobs(db, blobs); err != nil {
						logger.Warn("sweeping orphan blobs failed", "error", err)
					} else if n > 0 {
						logger.Info("removed orphan blob files", "count", n)
					}
				}
			}
		}
	}()
	return done
}

// sweepOrphanBlobs deletes blob files that have no metadata row, returning
// how many were removed.
func sweepOrphanBlobs(db *sql.DB, blobs *blobstore.Store) (int, error) {
	var orphans []string
	if err := blobs.EachStoredID(func(blobID string) error {
		exists, err := store.BlobIDExists(db, blobID)
		if err != nil {
			return err
		}
		if !exists {
			orphans = append(orphans, blobID)
		}
		return nil
	}); err != nil {
		return 0, err
	}
	removed := 0
	for _, id := range orphans {
		if err := blobs.Remove(id); err == nil {
			removed++
		}
	}
	return removed, nil
}

// runMessageCleanup starts a background goroutine that periodically purges
// message-queue entries past their retention window, until ctx is
// cancelled. The returned channel is closed once the goroutine has exited.
// runInviteCleanup starts a background goroutine that periodically removes
// invite codes which expired without being redeemed. Redeemed codes are left
// alone deliberately -- see store.PurgeExpiredInviteCodes.
func runInviteCleanup(ctx context.Context, db *sql.DB, logger *slog.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(inviteCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := store.PurgeExpiredInviteCodes(db, time.Now())
				if err != nil {
					logger.Warn("invite cleanup failed", "error", err)
					continue
				}
				if n > 0 {
					logger.Info("purged expired invite codes", "count", n)
				}
			}
		}
	}()
	return done
}

// runStatsSnapshot starts a background goroutine that records one server
// stats snapshot (internal/api's CurrentStatsSnapshot -- the same figures
// GET /v1/admin/stats reports live) immediately, so the admin statistics
// page has a first data point right after startup instead of waiting a full
// statsSnapshotInterval, and then one more every statsSnapshotInterval
// after that, pruning anything past statsSnapshotRetention on each tick.
// The returned channel is closed once the goroutine has exited.
func runStatsSnapshot(ctx context.Context, a *api.API, logger *slog.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		takeStatsSnapshot(a, logger)

		ticker := time.NewTicker(statsSnapshotInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				takeStatsSnapshot(a, logger)
			}
		}
	}()
	return done
}

// takeStatsSnapshot computes and records one stats_snapshots row, then
// prunes anything past statsSnapshotRetention. Failures are logged, never
// fatal -- a missed snapshot just leaves a gap in the history chart.
func takeStatsSnapshot(a *api.API, logger *slog.Logger) {
	snapshot, err := a.CurrentStatsSnapshot()
	if err != nil {
		logger.Warn("computing server stats snapshot failed", "error", err)
		return
	}
	if err := store.InsertStatsSnapshot(a.DB, snapshot); err != nil {
		logger.Warn("recording server stats snapshot failed", "error", err)
		return
	}
	if n, err := store.PruneStatsSnapshots(a.DB, snapshot.CapturedAt.Add(-statsSnapshotRetention)); err != nil {
		logger.Warn("pruning old server stats snapshots failed", "error", err)
	} else if n > 0 {
		logger.Info("pruned old server stats snapshots", "count", n)
	}
}

func runMessageCleanup(ctx context.Context, db *sql.DB, logger *slog.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(messageCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := store.PurgeExpiredMessages(db, time.Now())
				if err != nil {
					logger.Warn("message cleanup failed", "error", err)
					continue
				}
				if n > 0 {
					logger.Info("purged expired messages", "count", n)
				}
			}
		}
	}()
	return done
}
