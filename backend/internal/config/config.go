package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config holds all application configuration parsed from environment variables.
type Config struct {
	// Server
	Port int    `env:"PORT" envDefault:"8080"`
	Env  string `env:"ENV" envDefault:"development"`

	// Database
	DatabaseURL string `env:"DATABASE_URL,required"`

	// JWT
	JWTSecret       string        `env:"JWT_SECRET,required"`
	JWTAccessExpiry time.Duration `env:"JWT_ACCESS_EXPIRY" envDefault:"15m"`
	JWTRefreshExpiry time.Duration `env:"JWT_REFRESH_EXPIRY" envDefault:"720h"`

	// OAuth2
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`
	GoogleRedirectURL  string `env:"GOOGLE_REDIRECT_URL"`
	GitHubClientID     string `env:"GITHUB_CLIENT_ID"`
	GitHubClientSecret string `env:"GITHUB_CLIENT_SECRET"`
	GitHubRedirectURL  string `env:"GITHUB_REDIRECT_URL"`

	// MinIO / S3
	S3Endpoint      string        `env:"S3_ENDPOINT" envDefault:"minio:9000"`
	S3AccessKey     string        `env:"S3_ACCESS_KEY,required"`
	S3SecretKey     string        `env:"S3_SECRET_KEY,required"`
	S3Bucket        string        `env:"S3_BUCKET" envDefault:"drawgo"`
	S3UseSSL        bool          `env:"S3_USE_SSL" envDefault:"false"`
	S3Region        string        `env:"S3_REGION" envDefault:"us-east-1"`
	S3PresignExpiry time.Duration `env:"S3_PRESIGN_EXPIRY" envDefault:"15m"`

	// HTTP Server Timeouts
	ServerReadTimeout  time.Duration `env:"SERVER_READ_TIMEOUT" envDefault:"15s"`
	ServerWriteTimeout time.Duration `env:"SERVER_WRITE_TIMEOUT" envDefault:"60s"`
	ServerIdleTimeout  time.Duration `env:"SERVER_IDLE_TIMEOUT" envDefault:"120s"`

	// Request Body Limits (bytes)
	MaxBodySize        int64 `env:"MAX_BODY_SIZE" envDefault:"1048576"`           // 1 MB
	BoardSaveMaxBody   int64 `env:"BOARD_SAVE_MAX_BODY" envDefault:"16777216"`    // 16 MB
	FileUploadMaxBody  int64 `env:"FILE_UPLOAD_MAX_BODY" envDefault:"52428800"`   // 50 MB
	MaxFileSize        int64 `env:"MAX_FILE_SIZE" envDefault:"26214400"`          // 25 MB

	// Route Timeouts
	APIReadTimeout    time.Duration `env:"API_READ_TIMEOUT" envDefault:"10s"`
	APIWriteTimeout   time.Duration `env:"API_WRITE_TIMEOUT" envDefault:"30s"`
	FileUploadTimeout time.Duration `env:"FILE_UPLOAD_TIMEOUT" envDefault:"120s"`

	// Brute-Force Protection
	BruteForceMaxAttempts int           `env:"BRUTEFORCE_MAX_ATTEMPTS" envDefault:"5"`
	BruteForceWindow      time.Duration `env:"BRUTEFORCE_WINDOW" envDefault:"15m"`
	BruteForceLockout     time.Duration `env:"BRUTEFORCE_LOCKOUT" envDefault:"15m"`

	// Rate Limiting
	RateLimitRequestsPerMin int `env:"RATE_LIMIT_REQUESTS_PER_MINUTE" envDefault:"60"`
	RateLimitAuthPerMin     int `env:"RATE_LIMIT_AUTH_PER_MINUTE" envDefault:"10"`
	RateLimitUploadPerMin   int `env:"RATE_LIMIT_UPLOAD_PER_MINUTE" envDefault:"30"`
	RateLimitWSPerMin       int `env:"RATE_LIMIT_WS_PER_MINUTE" envDefault:"10"`

	// Logging
	LogLevel      string `env:"LOG_LEVEL" envDefault:"info"`
	LogFormat     string `env:"LOG_FORMAT" envDefault:"json"`
	LogBufferSize int    `env:"LOG_BUFFER_SIZE" envDefault:"5000"`

	// CORS
	CORSAllowedOrigins string `env:"CORS_ALLOWED_ORIGINS" envDefault:"http://localhost:3021"`

	// WebSocket
	WSMaxConnsPerBoard    int           `env:"WS_MAX_CONNECTIONS_PER_BOARD" envDefault:"50"`
	WSMaxMessageSize      int64         `env:"WS_MAX_MESSAGE_SIZE" envDefault:"1048576"`
	WSHeartbeatInterval   time.Duration `env:"WS_HEARTBEAT_INTERVAL" envDefault:"30s"`
	WSWriteTimeout        time.Duration `env:"WS_WRITE_TIMEOUT" envDefault:"10s"`
	WSCursorBatchInterval time.Duration `env:"WS_CURSOR_BATCH_INTERVAL" envDefault:"33ms"`

	// Backup
	BackupEnabled       bool          `env:"BACKUP_ENABLED" envDefault:"false"`
	BackupCron          string        `env:"BACKUP_CRON" envDefault:"0 3 * * *"`
	BackupKeepDaily     int           `env:"BACKUP_KEEP_DAILY" envDefault:"7"`
	BackupKeepWeekly    int           `env:"BACKUP_KEEP_WEEKLY" envDefault:"4"`
	BackupKeepMonthly   int           `env:"BACKUP_KEEP_MONTHLY" envDefault:"6"`
	BackupS3Bucket      string        `env:"BACKUP_S3_BUCKET" envDefault:"backups"`
	BackupEncryptionKey string        `env:"BACKUP_ENCRYPTION_KEY"`

	// Board history
	MaxVersionsPerBoard int `env:"MAX_VERSIONS_PER_BOARD" envDefault:"50"`

	// DB Pool
	DBPoolMinConns      int32         `env:"DB_POOL_MIN_CONNS" envDefault:"2"`
	DBPoolMaxConns      int32         `env:"DB_POOL_MAX_CONNS" envDefault:"25"`
	DBPoolMaxLife       time.Duration `env:"DB_POOL_MAX_LIFETIME" envDefault:"1h"`
	DBPoolIdleTime      time.Duration `env:"DB_POOL_IDLE_TIMEOUT" envDefault:"30m"`
	DBHealthCheckPeriod time.Duration `env:"DB_HEALTH_CHECK_PERIOD" envDefault:"30s"`

	// Server tuning
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"30s"`
	TrustedProxies  string        `env:"TRUSTED_PROXIES"`

	// Demo User (optional — seeded on startup if email is set)
	DemoUserEmail    string `env:"DEMO_USER_EMAIL"`
	DemoUserPassword string `env:"DEMO_USER_PASSWORD"`
	DemoUserName     string `env:"DEMO_USER_NAME"`
}

// Load parses environment variables into the Config struct.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if len(cfg.JWTSecret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters")
	}
	return cfg, nil
}

// IsProd returns true if the environment is production.
func (c *Config) IsProd() bool {
	return c.Env == "production"
}
