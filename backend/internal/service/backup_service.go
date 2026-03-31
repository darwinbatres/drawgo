package service

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/darwinbatres/drawgo/backend/internal/config"
	"github.com/darwinbatres/drawgo/backend/internal/models"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/apierror"
	"github.com/darwinbatres/drawgo/backend/internal/repository"
	"github.com/darwinbatres/drawgo/backend/internal/storage"
)

// BackupService handles database backup and restore operations.
type BackupService struct {
	repo   repository.BackupRepo
	audit  repository.AuditRepo
	s3     storage.ObjectStorage
	cfg    *config.Config
	log    zerolog.Logger
}

// NewBackupService creates a BackupService.
func NewBackupService(
	repo repository.BackupRepo,
	audit repository.AuditRepo,
	s3 storage.ObjectStorage,
	cfg *config.Config,
	log zerolog.Logger,
) *BackupService {
	return &BackupService{
		repo:  repo,
		audit: audit,
		s3:    s3,
		cfg:   cfg,
		log:   log,
	}
}

// CreateBackup runs pg_dump, uploads the result to S3, and records metadata.
func (s *BackupService) CreateBackup(ctx context.Context, backupType, actorID string) (*models.BackupMetadata, *apierror.Error) {
	start := time.Now()

	// Create metadata record (in_progress)
	meta, err := s.repo.CreateMetadata(ctx, backupType)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to create backup metadata")
		return nil, apierror.ErrInternal
	}

	// Run pg_dump
	dump, dumpErr := s.runPgDump(ctx)
	durationMs := int(time.Since(start).Milliseconds())

	if dumpErr != nil {
		errMsg := dumpErr.Error()
		_ = s.repo.FailMetadata(ctx, meta.ID, errMsg, durationMs)
		s.log.Error().Err(dumpErr).Msg("pg_dump failed")
		return nil, apierror.ErrInternal.WithMessage("Backup failed")
	}

	// Generate filename and storage key
	ts := time.Now().UTC().Format("20060102-150405")
	filename := fmt.Sprintf("excalidraw-%s-%s.sql", ts, meta.ID[:8])
	storageKey := fmt.Sprintf("backups/%s/%s", time.Now().UTC().Format("2006/01"), filename)
	sizeBytes := int64(len(dump))

	// Upload to S3 backup bucket
	reader := bytes.NewReader(dump)
	if err := s.s3.UploadToBucket(ctx, s.cfg.BackupS3Bucket, storageKey, reader, sizeBytes, "application/sql"); err != nil {
		errMsg := err.Error()
		_ = s.repo.FailMetadata(ctx, meta.ID, errMsg, durationMs)
		s.log.Error().Err(err).Msg("backup upload to S3 failed")
		return nil, apierror.ErrInternal.WithMessage("Backup upload failed")
	}

	durationMs = int(time.Since(start).Milliseconds())

	// Mark completed
	if err := s.repo.CompleteMetadata(ctx, meta.ID, filename, storageKey, sizeBytes, durationMs); err != nil {
		s.log.Error().Err(err).Msg("failed to complete backup metadata")
		return nil, apierror.ErrInternal
	}

	// Re-read completed record
	completed, err := s.repo.GetMetadata(ctx, meta.ID)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to read completed backup metadata")
		return nil, apierror.ErrInternal
	}

	// Audit event
	s.auditLog(ctx, actorID, models.AuditActionBackupCreate, "backup", meta.ID, map[string]any{
		"type":     backupType,
		"filename": filename,
		"size":     sizeBytes,
	})

	s.log.Info().Str("id", meta.ID).Str("filename", filename).Int64("bytes", sizeBytes).Int("durationMs", durationMs).Msg("backup created")
	return completed, nil
}

// RestoreBackup downloads a backup from S3 and restores it via pg_restore/psql.
// A safety backup is created first.
func (s *BackupService) RestoreBackup(ctx context.Context, backupID, actorID string) *apierror.Error {
	meta, err := s.repo.GetMetadata(ctx, backupID)
	if err != nil {
		return apierror.ErrNotFound.WithMessage("Backup not found")
	}
	if meta.Status != "completed" {
		return apierror.ErrBadRequest.WithMessage("Cannot restore a backup that is not completed")
	}

	// Safety: create a pre-restore backup first
	_, apiErr := s.CreateBackup(ctx, "pre_restore", actorID)
	if apiErr != nil {
		s.log.Error().Msg("failed to create pre-restore safety backup")
		return apierror.ErrInternal.WithMessage("Failed to create safety backup before restore")
	}

	// Download backup from S3
	reader, err := s.s3.DownloadFromBucket(ctx, s.cfg.BackupS3Bucket, meta.StorageKey)
	if err != nil {
		s.log.Error().Err(err).Str("key", meta.StorageKey).Msg("failed to download backup from S3")
		return apierror.ErrInternal.WithMessage("Failed to download backup")
	}
	defer reader.Close()

	// Read into buffer for psql stdin
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(reader); err != nil {
		s.log.Error().Err(err).Msg("failed to read backup data")
		return apierror.ErrInternal.WithMessage("Failed to read backup data")
	}

	// Restore via psql
	if err := s.runPsqlRestore(ctx, buf.Bytes()); err != nil {
		s.log.Error().Err(err).Msg("psql restore failed")
		return apierror.ErrInternal.WithMessage("Restore failed")
	}

	s.auditLog(ctx, actorID, models.AuditActionBackupRestore, "backup", backupID, map[string]any{
		"filename": meta.Filename,
	})

	s.log.Info().Str("backupID", backupID).Str("filename", meta.Filename).Msg("backup restored")
	return nil
}

// ListBackups returns paginated backup metadata.
func (s *BackupService) ListBackups(ctx context.Context, limit, offset int) ([]models.BackupMetadata, int, *apierror.Error) {
	backups, total, err := s.repo.ListMetadata(ctx, limit, offset)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to list backups")
		return nil, 0, apierror.ErrInternal
	}
	return backups, total, nil
}

// GetBackup returns a single backup's metadata.
func (s *BackupService) GetBackup(ctx context.Context, id string) (*models.BackupMetadata, *apierror.Error) {
	meta, err := s.repo.GetMetadata(ctx, id)
	if err != nil {
		return nil, apierror.ErrNotFound.WithMessage("Backup not found")
	}
	return meta, nil
}

// GetDownloadURL returns a presigned S3 URL to download the backup file.
func (s *BackupService) GetDownloadURL(ctx context.Context, id string) (string, *apierror.Error) {
	meta, err := s.repo.GetMetadata(ctx, id)
	if err != nil {
		return "", apierror.ErrNotFound.WithMessage("Backup not found")
	}
	if meta.Status != "completed" {
		return "", apierror.ErrBadRequest.WithMessage("Backup is not available for download")
	}

	url, err := s.s3.PresignedURLFromBucket(ctx, s.cfg.BackupS3Bucket, meta.StorageKey)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to generate backup download URL")
		return "", apierror.ErrInternal
	}
	return url, nil
}

// DeleteBackup removes a backup from S3 and the database.
func (s *BackupService) DeleteBackup(ctx context.Context, id, actorID string) *apierror.Error {
	meta, err := s.repo.GetMetadata(ctx, id)
	if err != nil {
		return apierror.ErrNotFound.WithMessage("Backup not found")
	}

	// Delete from S3 if completed (has a real storage key)
	if meta.StorageKey != "" {
		if err := s.s3.DeleteFromBucket(ctx, s.cfg.BackupS3Bucket, meta.StorageKey); err != nil {
			s.log.Error().Err(err).Str("key", meta.StorageKey).Msg("failed to delete backup from S3")
		}
	}

	if err := s.repo.DeleteMetadata(ctx, id); err != nil {
		s.log.Error().Err(err).Msg("failed to delete backup metadata")
		return apierror.ErrInternal
	}

	s.auditLog(ctx, actorID, models.AuditActionBackupDelete, "backup", id, map[string]any{
		"filename": meta.Filename,
	})

	return nil
}

// RotateBackups applies the retention policy and removes expired backups.
func (s *BackupService) RotateBackups(ctx context.Context) (int, error) {
	schedule, err := s.repo.GetSchedule(ctx)
	if err != nil {
		return 0, fmt.Errorf("reading backup schedule: %w", err)
	}

	expired, err := s.repo.ListExpiredForRotation(ctx, schedule.KeepDaily, schedule.KeepWeekly, schedule.KeepMonthly)
	if err != nil {
		return 0, fmt.Errorf("listing expired backups: %w", err)
	}

	deleted := 0
	for _, m := range expired {
		if m.StorageKey != "" {
			if err := s.s3.DeleteFromBucket(ctx, s.cfg.BackupS3Bucket, m.StorageKey); err != nil {
				s.log.Error().Err(err).Str("id", m.ID).Msg("failed to delete expired backup from S3")
				continue
			}
		}
		if err := s.repo.DeleteMetadata(ctx, m.ID); err != nil {
			s.log.Error().Err(err).Str("id", m.ID).Msg("failed to delete expired backup metadata")
			continue
		}
		deleted++
	}

	if deleted > 0 {
		s.log.Info().Int("deleted", deleted).Msg("rotated expired backups")
	}
	return deleted, nil
}

// GetSchedule returns the current backup schedule.
func (s *BackupService) GetSchedule(ctx context.Context) (*models.BackupSchedule, *apierror.Error) {
	sched, err := s.repo.GetSchedule(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to get backup schedule")
		return nil, apierror.ErrInternal
	}
	return sched, nil
}

// UpdateSchedule updates the backup schedule settings.
func (s *BackupService) UpdateSchedule(ctx context.Context, actorID string, enabled bool, cronExpr string, keepDaily, keepWeekly, keepMonthly int) (*models.BackupSchedule, *apierror.Error) {
	// Validate cron expression
	if err := validateCron(cronExpr); err != nil {
		return nil, apierror.ErrBadRequest.WithMessage("Invalid cron expression: " + err.Error())
	}

	// Validate retention values
	if keepDaily < 1 || keepWeekly < 0 || keepMonthly < 0 {
		return nil, apierror.ErrBadRequest.WithMessage("Keep daily must be >= 1, weekly and monthly >= 0")
	}

	sched, err := s.repo.UpdateSchedule(ctx, enabled, cronExpr, keepDaily, keepWeekly, keepMonthly)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to update backup schedule")
		return nil, apierror.ErrInternal
	}

	s.auditLog(ctx, actorID, models.AuditActionBackupScheduleUpdate, "backup_schedule", "default", map[string]any{
		"enabled":     enabled,
		"cron":        cronExpr,
		"keepDaily":   keepDaily,
		"keepWeekly":  keepWeekly,
		"keepMonthly": keepMonthly,
	})

	return sched, nil
}

// runPgDump executes pg_dump and returns the output.
// Credentials are passed via environment variables (not CLI args) to prevent
// leaking the database password in /proc or process listings.
func (s *BackupService) runPgDump(ctx context.Context) ([]byte, error) {
	pgEnv, dbName, err := parseDatabaseURL(s.cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("pg_dump: invalid DATABASE_URL: %w", err)
	}

	cmd := exec.CommandContext(ctx, "pg_dump",
		"--dbname="+dbName,
		"--format=plain",
		"--no-owner",
		"--no-privileges",
		"--clean",
		"--if-exists",
	)
	cmd.Env = append(cmd.Environ(), pgEnv...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pg_dump: %w: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// runPsqlRestore executes psql to restore a SQL dump.
// Credentials are passed via environment variables.
func (s *BackupService) runPsqlRestore(ctx context.Context, data []byte) error {
	pgEnv, dbName, err := parseDatabaseURL(s.cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("psql: invalid DATABASE_URL: %w", err)
	}

	cmd := exec.CommandContext(ctx, "psql",
		"--dbname="+dbName,
		"--single-transaction",
		"--quiet",
	)
	cmd.Env = append(cmd.Environ(), pgEnv...)
	cmd.Stdin = bytes.NewReader(data)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("psql restore: %w: %s", err, stderr.String())
	}

	return nil
}

// parseDatabaseURL extracts connection parameters from a PostgreSQL URL and
// returns them as environment variable strings (PGHOST, PGPORT, etc.) plus
// the database name. This avoids passing credentials on the CLI.
func parseDatabaseURL(dbURL string) (env []string, dbName string, err error) {
	u, err := url.Parse(dbURL)
	if err != nil {
		return nil, "", err
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	user := u.User.Username()
	password, _ := u.User.Password()
	dbName = strings.TrimPrefix(u.Path, "/")

	env = []string{
		"PGHOST=" + host,
		"PGPORT=" + port,
		"PGUSER=" + user,
		"PGPASSWORD=" + password,
	}

	// Pass through sslmode if specified
	if sslmode := u.Query().Get("sslmode"); sslmode != "" {
		env = append(env, "PGSSLMODE="+sslmode)
	}

	return env, dbName, nil
}

// auditLog is a convenience method for fire-and-forget audit logging.
func (s *BackupService) auditLog(ctx context.Context, actorID, action, targetType, targetID string, metadata map[string]any) {
	var actor *string
	if actorID != "" {
		actor = &actorID
	}
	if err := s.audit.Log(ctx, "", actor, action, targetType, targetID, nil, nil, metadata); err != nil {
		s.log.Error().Err(err).Str("action", action).Msg("failed to log audit event")
	}
}

// validateCron does a basic validation of a cron expression (5 fields).
func validateCron(expr string) error {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return fmt.Errorf("expected 5 fields, got %d", len(fields))
	}
	// Each field should be non-empty and contain only valid cron characters
	for _, f := range fields {
		for _, c := range f {
			if !strings.ContainsRune("0123456789*,/-", c) {
				return fmt.Errorf("invalid character %q in field %q", string(c), f)
			}
		}
	}
	return nil
}
