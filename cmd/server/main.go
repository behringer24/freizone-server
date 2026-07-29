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
)

const (
	nonceCleanupInterval   = 10 * time.Minute
	messageCleanupInterval = 1 * time.Hour

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

	<-nonceCleanupDone
	<-messageCleanupDone
	<-blobCleanupDone
	return nil
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
// Three jobs, all bounded per tick so a large backlog is worked off across
// several rounds rather than in one long stall:
//   - expired blobs: file unlinked, then the row dropped.
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
