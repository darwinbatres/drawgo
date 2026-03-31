package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/darwinbatres/drawgo/backend/internal/config"
	"github.com/darwinbatres/drawgo/backend/internal/database"
	"github.com/darwinbatres/drawgo/backend/internal/handler"
	"github.com/darwinbatres/drawgo/backend/internal/middleware"
	"github.com/darwinbatres/drawgo/backend/internal/models"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/jwt"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/logbuffer"
	"github.com/darwinbatres/drawgo/backend/internal/realtime"
	"github.com/darwinbatres/drawgo/backend/internal/repository"
	"github.com/darwinbatres/drawgo/backend/internal/router"
	"github.com/darwinbatres/drawgo/backend/internal/service"
	"github.com/darwinbatres/drawgo/backend/internal/storage"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Configuration ---
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// --- Logging (with ring buffer for /api/v1/logs) ---
	log, logBuf := setupLogger(cfg)
	log.Info().Str("env", cfg.Env).Int("port", cfg.Port).Msg("starting excalidraw-go backend")

	// --- Database Migrations ---
	log.Info().Msg("running database migrations")
	if err = database.Migrate(cfg.DatabaseURL, log); err != nil {
		log.Fatal().Err(err).Msg("failed to run migrations")
	}

	// --- Database Pool ---
	pool, err := database.New(ctx, cfg, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()

	// --- JWT Manager ---
	s3Client, err := storage.NewS3Client(ctx, cfg, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize S3 storage")
	}

	jwtManager := jwt.NewManager(cfg.JWTSecret, cfg.JWTAccessExpiry, cfg.JWTRefreshExpiry)

	// --- Repositories ---
	userRepo := repository.NewUserRepository(pool)
	refreshTokenRepo := repository.NewRefreshTokenRepository(pool)
	accountRepo := repository.NewAccountRepository(pool)
	auditRepo := repository.NewAuditRepository(pool)
	orgRepo := repository.NewOrgRepository(pool)
	membershipRepo := repository.NewMembershipRepository(pool)
	boardRepo := repository.NewBoardRepository(pool)
	boardVersionRepo := repository.NewBoardVersionRepository(pool)
	boardPermissionRepo := repository.NewBoardPermissionRepository(pool)
	boardAssetRepo := repository.NewBoardAssetRepository(pool)
	shareLinkRepo := repository.NewShareLinkRepository(pool)
	backupRepo := repository.NewBackupRepository(pool)

	// --- Seed Demo User (if configured) ---
	if cfg.DemoUserEmail != "" {
		seedDemoUser(ctx, pool, userRepo, orgRepo, membershipRepo, cfg, log)
	}

	// --- Services ---
	authService := service.NewAuthService(userRepo, refreshTokenRepo, auditRepo, jwtManager, log)
	oauthService := service.NewOAuthService(cfg, userRepo, accountRepo, refreshTokenRepo, auditRepo, jwtManager, log)
	accessService := service.NewAccessService(membershipRepo)
	accessService.WithBoardRepos(boardRepo, boardPermissionRepo)
	orgService := service.NewOrgService(pool, orgRepo, membershipRepo, userRepo, auditRepo, accessService, log)
	boardService := service.NewBoardService(pool, boardRepo, boardVersionRepo, auditRepo, accessService, log, cfg.MaxVersionsPerBoard)
	fileService := service.NewFileService(boardAssetRepo, boardRepo, boardVersionRepo, s3Client, accessService, auditRepo, log, cfg.MaxFileSize)
	boardService.SetFileService(fileService)
	auditService := service.NewAuditService(auditRepo, boardAssetRepo, backupRepo, accessService, s3Client, log, cfg.S3Bucket, cfg.BackupS3Bucket)
	cleanupService := service.NewCleanupService(boardAssetRepo, boardRepo, boardVersionRepo, auditRepo, s3Client, log)
	_ = cleanupService // wired for scheduled cleanup; not yet exposed via HTTP
	shareService := service.NewShareService(shareLinkRepo, boardRepo, auditRepo, accessService, log)
	backupService := service.NewBackupService(backupRepo, auditRepo, s3Client, cfg, log)

	// --- Backup Scheduler ---
	backupScheduler := service.NewBackupScheduler(backupService, log)
	if cfg.BackupEnabled {
		go backupScheduler.Run(ctx)
	}

	// --- WebSocket Hub ---
	hub := realtime.NewHub(realtime.HubConfig{
		MaxConnsPerBoard:  cfg.WSMaxConnsPerBoard,
		HeartbeatInterval: cfg.WSHeartbeatInterval,
		CursorInterval:    cfg.WSCursorBatchInterval,
	}, log)
	hub.Run(ctx)
	defer hub.Shutdown()

	// --- Brute-Force Protector ---
	bruteForce := middleware.NewBruteForce(middleware.BruteForceConfig{
		MaxAttempts: cfg.BruteForceMaxAttempts,
		Window:      cfg.BruteForceWindow,
		Lockout:     cfg.BruteForceLockout,
	})

	// --- Request Metrics ---
	requestMetrics := middleware.NewRequestMetrics()
	auditService.SetRequestMetrics(requestMetrics)
	auditService.SetBruteForce(bruteForce)
	auditService.SetLogBuffer(logBuf)

	// --- Handlers ---
	healthHandler := handler.NewHealthHandler(pool, s3Client)
	authHandler := handler.NewAuthHandler(authService, cfg, bruteForce, jwtManager)
	oauthHandler := handler.NewOAuthHandler(oauthService)
	orgHandler := handler.NewOrgHandler(orgService)
	memberHandler := handler.NewMemberHandler(orgService)
	boardHandler := handler.NewBoardHandler(boardService)
	versionHandler := handler.NewVersionHandler(boardService)
	fileHandler := handler.NewFileHandler(fileService, cfg, log)
	auditHandler := handler.NewAuditHandler(auditService)
	shareHandler := handler.NewShareHandler(shareService)
	backupHandler := handler.NewBackupHandler(backupService)
	logHandler := handler.NewLogHandler(logBuf)
	wsHandler := handler.NewWSHandler(hub, jwtManager, shareService, accessService, log, strings.Split(cfg.CORSAllowedOrigins, ","), cfg)

	// --- Router ---
	r := router.New(router.Deps{
		Config:         cfg,
		Log:            log,
		JWTManager:     jwtManager,
		BruteForce:     bruteForce,
		RequestMetrics: requestMetrics,
		Access:         accessService,
		Health:         healthHandler,
		Auth:       authHandler,
		OAuth:      oauthHandler,
		Org:        orgHandler,
		Member:     memberHandler,
		Board:      boardHandler,
		Version:    versionHandler,
		File:       fileHandler,
		Audit:      auditHandler,
		Share:      shareHandler,
		Backup:     backupHandler,
		LogView:    logHandler,
		WS:         wsHandler,
	})

	// --- HTTP Server ---
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      r,
		ReadTimeout:  cfg.ServerReadTimeout,
		WriteTimeout: cfg.ServerWriteTimeout,
		IdleTimeout:  cfg.ServerIdleTimeout,
	}

	// --- Graceful Shutdown ---
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	// Start brute-force cleanup goroutine (stops on shutdown)
	bfDone := make(chan struct{})
	bruteForce.StartCleanup(bfDone)

	go func() {
		log.Info().Str("addr", srv.Addr).Msg("HTTP server listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server failed")
		}
	}()

	<-done
	log.Info().Msg("shutdown signal received")
	shutdownStart := time.Now()
	close(bfDone)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown error")
	}

	log.Info().Dur("elapsed", time.Since(shutdownStart)).Msg("server stopped gracefully")
}

// setupLogger configures zerolog based on environment and returns both the
// logger and the ring buffer that captures log entries for the /api/v1/logs endpoint.
func setupLogger(cfg *config.Config) (zerolog.Logger, *logbuffer.RingBuffer) {
	// Set global log level
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	if cfg.LogFormat == "console" || !cfg.IsProd() {
		// Dev: ring buffer wraps a console writer so both buffer and terminal get output.
		buf := logbuffer.New(cfg.LogBufferSize, zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
		logger := zerolog.New(buf).
			With().
			Timestamp().
			Caller().
			Logger()
		return logger, buf
	}

	// Production: ring buffer wraps raw stdout (JSON output).
	buf := logbuffer.New(cfg.LogBufferSize, os.Stdout)
	logger := zerolog.New(buf).
		With().
		Timestamp().
		Logger()
	return logger, buf
}

// seedDemoUser creates the demo user and a default organization on startup if they do not already exist.
func seedDemoUser(ctx context.Context, pool *pgxpool.Pool, users repository.UserRepo, orgs repository.OrgRepo, memberships repository.MembershipRepo, cfg *config.Config, log zerolog.Logger) {
	if cfg.DemoUserPassword == "" {
		log.Warn().Msg("DEMO_USER_EMAIL is set but DEMO_USER_PASSWORD is empty — skipping demo user seed")
		return
	}

	exists, err := users.ExistsByEmail(ctx, cfg.DemoUserEmail)
	if err != nil {
		log.Error().Err(err).Msg("failed to check demo user existence")
		return
	}
	if exists {
		log.Info().Str("email", cfg.DemoUserEmail).Msg("demo user already exists — skipping seed")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.DemoUserPassword), service.BcryptCost)
	if err != nil {
		log.Error().Err(err).Msg("failed to hash demo user password")
		return
	}
	hashStr := string(hash)

	var name *string
	if cfg.DemoUserName != "" {
		name = &cfg.DemoUserName
	}

	user, err := users.Create(ctx, cfg.DemoUserEmail, name, &hashStr)
	if err != nil {
		log.Error().Err(err).Msg("failed to create demo user")
		return
	}
	log.Info().Str("id", user.ID).Str("email", cfg.DemoUserEmail).Msg("demo user seeded")

	// Create a default organization for the demo user
	tx, err := pool.Begin(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to begin transaction for demo org")
		return
	}
	defer tx.Rollback(ctx)

	org, err := orgs.CreateInTx(ctx, tx, "Personal", "personal")
	if err != nil {
		log.Error().Err(err).Msg("failed to create demo org")
		return
	}

	if _, err := memberships.CreateInTx(ctx, tx, org.ID, user.ID, models.OrgRoleOwner); err != nil {
		log.Error().Err(err).Msg("failed to create demo org membership")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		log.Error().Err(err).Msg("failed to commit demo org creation")
		return
	}

	log.Info().Str("orgId", org.ID).Str("orgName", org.Name).Msg("demo organization seeded")
}
