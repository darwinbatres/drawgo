package router

import (
	"strings"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/rs/zerolog"

	"github.com/darwinbatres/drawgo/backend/internal/config"
	"github.com/darwinbatres/drawgo/backend/internal/handler"
	"github.com/darwinbatres/drawgo/backend/internal/middleware"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/jwt"
	"github.com/darwinbatres/drawgo/backend/internal/service"
)

// Deps holds all dependencies needed to wire up routes.
type Deps struct {
	Config         *config.Config
	Log            zerolog.Logger
	JWTManager     *jwt.Manager
	BruteForce     *middleware.BruteForce
	RequestMetrics *middleware.RequestMetrics
	Access         *service.AccessService
	// Handlers
	Health  *handler.HealthHandler
	Auth    *handler.AuthHandler
	OAuth   *handler.OAuthHandler
	Org     *handler.OrgHandler
	Member  *handler.MemberHandler
	Board   *handler.BoardHandler
	Version *handler.VersionHandler
	File    *handler.FileHandler
	Audit   *handler.AuditHandler
	Share   *handler.ShareHandler
	WS      *handler.WSHandler
	Backup  *handler.BackupHandler
	LogView *handler.LogHandler
}

// New creates a fully configured chi router with all middleware and routes.
func New(deps Deps) chi.Router {
	r := chi.NewRouter()

	// --- Global middleware stack (order matters) ---
	r.Use(chimw.RequestID)
	r.Use(middleware.TrustedRealIP(deps.Config.TrustedProxies))
	r.Use(middleware.Recovery(deps.Log))
	r.Use(middleware.Logger(deps.Log))
	if deps.RequestMetrics != nil {
		r.Use(deps.RequestMetrics.Middleware)
	}
	r.Use(middleware.Security(deps.Config.CORSAllowedOrigins))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   strings.Split(deps.Config.CORSAllowedOrigins, ","),
		AllowedMethods:   []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-Id", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(middleware.RateLimit(deps.Config))
	r.Use(middleware.MaxBodySize(deps.Config.MaxBodySize))
	r.Use(chimw.Compress(5))
	r.Use(middleware.CSRF(deps.Config.CORSAllowedOrigins))

	// --- API v1 routes ---
	r.Route("/api/v1", func(api chi.Router) {
		// Read timeout for most API routes
		api.Use(middleware.Timeout(deps.Config.APIReadTimeout))
		// Default: no caching for API responses
		api.Use(middleware.CacheControl(middleware.CacheNoStore))

		// Public endpoints (no auth required)
		api.Get("/health", deps.Health.Health)
		api.Get("/ready", deps.Health.Ready)
		api.Get("/version", deps.Health.Version)

		// Auth routes (stricter rate limiting + brute-force protection)
		api.Group(func(auth chi.Router) {
			auth.Use(middleware.AuthRateLimit(deps.Config))
			auth.Use(deps.BruteForce.Middleware())
			auth.Post("/auth/register", deps.Auth.Register)
			auth.Post("/auth/login", deps.Auth.Login)
			auth.Post("/auth/refresh", deps.Auth.Refresh)

			// OAuth routes
			auth.Get("/auth/oauth/{provider}", deps.OAuth.Authorize)
			auth.Get("/auth/oauth/{provider}/callback", deps.OAuth.Callback)
		})

		// Logout requires authentication
		api.Group(func(authed chi.Router) {
			authed.Use(middleware.Auth(deps.JWTManager))
			authed.Post("/auth/logout", deps.Auth.Logout)
			authed.Get("/auth/me", deps.Auth.Me)
		})

		// Protected routes (require authentication)
		api.Group(func(protected chi.Router) {
			protected.Use(middleware.Auth(deps.JWTManager))

			// Write routes have longer timeout
			protected.Group(func(write chi.Router) {
				write.Use(middleware.Timeout(deps.Config.APIWriteTimeout))

				// Board save gets a larger body limit
				write.Group(func(save chi.Router) {
					save.Use(middleware.MaxBodySize(deps.Config.BoardSaveMaxBody))
					save.Post("/boards/{id}/versions", deps.Version.Save)
				})

				// File upload gets the largest body limit
				write.Group(func(upload chi.Router) {
					upload.Use(middleware.MaxBodySize(deps.Config.FileUploadMaxBody))
					upload.Use(middleware.Timeout(deps.Config.FileUploadTimeout))
					upload.Use(middleware.UploadRateLimit(deps.Config))
					upload.Post("/boards/{id}/files", deps.File.Upload)
				})
			})

			// Organization routes
			protected.Post("/orgs", deps.Org.Create)
			protected.Get("/orgs", deps.Org.List)
			protected.Patch("/orgs/{id}", deps.Org.Update)
			protected.Delete("/orgs/{id}", deps.Org.Delete)

			protected.Get("/orgs/{id}/storage", deps.File.OrgStorage)

			// Member routes
			protected.Get("/orgs/{id}/members", deps.Member.List)
			protected.Post("/orgs/{id}/members", deps.Member.Invite)
			protected.Patch("/orgs/{id}/members/{membershipId}", deps.Member.UpdateRole)
			protected.Delete("/orgs/{id}/members/{membershipId}", deps.Member.Remove)

			// Board routes (scoped to org)
			protected.Post("/orgs/{id}/boards", deps.Board.Create)
			protected.Get("/orgs/{id}/boards", deps.Board.List)

			// Board routes (direct)
			protected.Get("/boards/{id}", deps.Board.Get)
			protected.Patch("/boards/{id}", deps.Board.Update)
			protected.Delete("/boards/{id}", deps.Board.Delete)

			// Board file/storage routes
			protected.Get("/boards/{id}/files", deps.File.ListAssets)
			protected.Get("/boards/{id}/files/{fileId}", deps.File.Download)
			protected.Get("/boards/{id}/storage", deps.File.BoardStorage)

			// Version routes
			protected.Get("/boards/{id}/versions", deps.Version.List)
			protected.Get("/boards/{id}/versions/{version}", deps.Version.Get)
			protected.Post("/boards/{id}/versions/{version}/restore", deps.Version.Restore)

			// Audit routes
			protected.Get("/orgs/{id}/audit", deps.Audit.List)
			protected.Get("/orgs/{id}/audit/stats", deps.Audit.Stats)
			protected.Get("/orgs/{id}/stats", deps.Audit.OrgStats)

			// Share link routes (EDITOR+ on board)
			protected.Post("/boards/{id}/share", deps.Share.Create)
			protected.Get("/boards/{id}/share", deps.Share.List)
			protected.Delete("/boards/{id}/share/{linkId}", deps.Share.Revoke)

			// System admin routes (require OWNER of any org)
			protected.Group(func(admin chi.Router) {
				admin.Use(middleware.AdminOnly(deps.Access.RequireSystemAdmin))

				// System stats (admin)
				admin.Get("/stats", deps.Audit.SystemStats)

				// Log viewer (admin)
				admin.Get("/logs", deps.LogView.Query)
				admin.Get("/logs/summary", deps.LogView.Summary)

				// Backup routes (admin)
				admin.Post("/backups", deps.Backup.Create)
				admin.Get("/backups", deps.Backup.List)
				admin.Get("/backups/schedule", deps.Backup.GetSchedule)
				admin.Put("/backups/schedule", deps.Backup.UpdateSchedule)
				admin.Get("/backups/{id}", deps.Backup.Get)
				admin.Get("/backups/{id}/download", deps.Backup.Download)
				admin.Delete("/backups/{id}", deps.Backup.Delete)
				admin.Post("/backups/{id}/restore", deps.Backup.Restore)
			})

		})

		// Public endpoints — no auth required
		api.Get("/share/{token}", deps.Share.GetShared)

		// WebSocket — auth via query params (token= or share=)
		// NOTE: /ws/* routes are in the same group to avoid chi radix-tree
		// conflicts when the /ws/ prefix spans separate middleware groups.
		api.Group(func(ws chi.Router) {
			// Stats endpoint uses normal API rate limit + auth
			ws.Group(func(stats chi.Router) {
				stats.Use(middleware.Auth(deps.JWTManager))
				stats.Get("/ws/stats", deps.WS.Stats)
			})
			// WS upgrade uses WS-specific rate limit
			ws.Group(func(upgrade chi.Router) {
				upgrade.Use(middleware.WSRateLimit(deps.Config))
				upgrade.Get("/ws/boards/{id}", deps.WS.Upgrade)
			})
		})
	})

	return r
}
