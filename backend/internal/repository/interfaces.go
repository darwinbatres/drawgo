package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/darwinbatres/drawgo/backend/internal/models"
)

//go:generate mockgen -destination=../testutil/mocks/mock_repos.go -package=mocks github.com/darwinbatres/drawgo/backend/internal/repository UserRepo,RefreshTokenRepo,AccountRepo,AuditRepo,OrgRepo,MembershipRepo,BoardRepo,BoardVersionRepo,BoardPermissionRepo,BoardAssetRepo,ShareLinkRepo,BackupRepo

// UserRepo defines user persistence operations.
type UserRepo interface {
	Create(ctx context.Context, email string, name *string, passwordHash *string) (*models.User, error)
	GetByID(ctx context.Context, id string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	UpdateProfile(ctx context.Context, id string, name *string, image *string) error
	VerifyEmail(ctx context.Context, id string) error
	CreateOrGetByOAuth(ctx context.Context, email string, name *string, image *string, emailVerified bool) (*models.User, bool, error)
}

// RefreshTokenRepo defines refresh token persistence operations.
type RefreshTokenRepo interface {
	Create(ctx context.Context, userID, rawToken, userAgent, ip string, expiresAt time.Time) (*models.RefreshToken, error)
	GetByHash(ctx context.Context, rawToken string) (*models.RefreshToken, error)
	Rotate(ctx context.Context, oldTokenID, newTokenID string) error
	RevokeByID(ctx context.Context, tokenID string) error
	RevokeAllForUser(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
	IsTokenFamilyCompromised(ctx context.Context, rawToken string) (bool, string, error)
}

// AccountRepo defines OAuth account persistence operations.
type AccountRepo interface {
	Upsert(ctx context.Context, userID, provider, providerAccountID string, accessToken, refreshToken *string, expiresAt *int) (*models.Account, error)
	GetByProvider(ctx context.Context, provider, providerAccountID string) (*models.Account, error)
	ListByUser(ctx context.Context, userID string) ([]models.Account, error)
	Delete(ctx context.Context, id string) error
}

// AuditRepo defines audit log persistence operations.
type AuditRepo interface {
	Log(ctx context.Context, orgID string, actorID *string, action, targetType, targetID string, ip, userAgent *string, metadata map[string]any) error
	Query(ctx context.Context, params AuditQueryParams) (*AuditQueryResult, error)
	Stats(ctx context.Context, orgID string, since time.Time) (*AuditStats, error)
	CountAll(ctx context.Context) (*SystemCounts, error)
	CountAllByOrg(ctx context.Context, orgID string) (string, *OrgCounts, error)
	GetDatabaseStats(ctx context.Context) (*DatabaseStats, error)
	GetSystemStats(ctx context.Context) (*SystemStatsResult, error)
	GlobalCRUDBreakdown(ctx context.Context) (*CRUDBreakdown, error)
	OrgCRUDBreakdown(ctx context.Context, orgID string) (*CRUDBreakdown, error)
	PurgeOlderThan(ctx context.Context, orgID string, cutoff time.Time) (int64, error)
}

// OrgRepo defines organization persistence operations.
type OrgRepo interface {
	Create(ctx context.Context, name, slug string) (*models.Organization, error)
	CreateInTx(ctx context.Context, tx pgx.Tx, name, slug string) (*models.Organization, error)
	GetByID(ctx context.Context, id string) (*models.Organization, error)
	SlugExists(ctx context.Context, slug string) (bool, error)
	ListByUser(ctx context.Context, userID string) ([]OrgWithCounts, error)
	Update(ctx context.Context, id, name string) (*models.Organization, error)
	Delete(ctx context.Context, id string) error
	BoardCount(ctx context.Context, orgID string) (int, error)
}

// MembershipRepo defines membership persistence operations.
type MembershipRepo interface {
	Create(ctx context.Context, orgID, userID string, role models.OrgRole) (*models.Membership, error)
	CreateInTx(ctx context.Context, tx pgx.Tx, orgID, userID string, role models.OrgRole) (*models.Membership, error)
	GetByOrgAndUser(ctx context.Context, orgID, userID string) (*models.Membership, error)
	GetByID(ctx context.Context, id string) (*models.Membership, error)
	ListByOrg(ctx context.Context, orgID string) ([]models.MembershipWithUser, error)
	UpdateRole(ctx context.Context, id string, role models.OrgRole) (*models.Membership, error)
	Delete(ctx context.Context, id string) error
	CountByUser(ctx context.Context, userID string) (int, error)
	Exists(ctx context.Context, orgID, userID string) (bool, error)
	IsOwnerOfAny(ctx context.Context, userID string) (bool, error)
}

// BoardRepo defines board persistence operations.
type BoardRepo interface {
	CreateInTx(ctx context.Context, tx pgx.Tx, board *models.Board) error
	GetByID(ctx context.Context, id string) (*models.Board, error)
	GetByIDForUpdate(ctx context.Context, tx pgx.Tx, id string) (*models.Board, error)
	GetByIDWithVersion(ctx context.Context, id string) (*models.BoardWithVersion, error)
	Update(ctx context.Context, board *models.Board) error
	UpdateVersionInfoInTx(ctx context.Context, tx pgx.Tx, boardID, versionID, etag string, versionNumber int, searchContent *string, thumbnail *string) error
	Delete(ctx context.Context, id string) error
	Search(ctx context.Context, params BoardSearchParams) (*BoardSearchResult, error)
}

// BoardVersionRepo defines board version persistence operations.
type BoardVersionRepo interface {
	CreateInTx(ctx context.Context, tx pgx.Tx, v *models.BoardVersion) error
	GetByID(ctx context.Context, id string) (*models.BoardVersion, error)
	GetByBoardAndVersion(ctx context.Context, boardID string, version int) (*models.BoardVersion, error)
	ListByBoard(ctx context.Context, boardID string, limit, offset int) ([]BoardVersionWithCreator, int64, error)
	DataStorageByBoard(ctx context.Context, boardID string) (*BoardDataStorageInfo, error)
	DataStorageByOrg(ctx context.Context, orgID string) (*BoardDataStorageInfo, error)
	PruneOldVersions(ctx context.Context, boardID string, maxKeep int) (int64, error)
}

// BoardPermissionRepo defines board permission persistence operations.
type BoardPermissionRepo interface {
	GetByBoardAndUser(ctx context.Context, boardID, userID string) (*models.BoardPermission, error)
}

// BoardAssetRepo defines board asset persistence operations.
type BoardAssetRepo interface {
	Upsert(ctx context.Context, asset *models.BoardAsset) error
	GetByBoardAndFileID(ctx context.Context, boardID, fileID string) (*models.BoardAsset, error)
	ListByBoard(ctx context.Context, boardID string) ([]models.BoardAsset, error)
	Delete(ctx context.Context, id string) error
	DeleteByBoardAndFileID(ctx context.Context, boardID, fileID string) error
	StorageUsedByBoard(ctx context.Context, boardID string) (int64, error)
	StorageUsedByOrg(ctx context.Context, orgID string) (int64, error)
	FindBySHA256(ctx context.Context, boardID, sha256 string) (*models.BoardAsset, error)
	DeleteOrphaned(ctx context.Context, boardID string, activeFileIDs []string) ([]models.BoardAsset, error)
}

// ShareLinkRepo defines share link persistence operations.
type ShareLinkRepo interface {
	Create(ctx context.Context, boardID, createdBy string, role models.BoardRole, expiresAt *time.Time) (*models.ShareLink, error)
	GetByToken(ctx context.Context, tok string) (*models.ShareLink, error)
	GetByID(ctx context.Context, id string) (*models.ShareLink, error)
	ListByBoard(ctx context.Context, boardID string) ([]models.ShareLink, error)
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) (int64, error)
	DeleteByBoard(ctx context.Context, boardID string) error
}

// BackupRepo defines backup metadata persistence operations.
type BackupRepo interface {
	CreateMetadata(ctx context.Context, backupType string) (*models.BackupMetadata, error)
	CompleteMetadata(ctx context.Context, id, filename, storageKey string, sizeBytes int64, durationMs int) error
	FailMetadata(ctx context.Context, id, errMsg string, durationMs int) error
	GetMetadata(ctx context.Context, id string) (*models.BackupMetadata, error)
	ListMetadata(ctx context.Context, limit, offset int) ([]models.BackupMetadata, int, error)
	DeleteMetadata(ctx context.Context, id string) error
	ListExpiredForRotation(ctx context.Context, keepDaily, keepWeekly, keepMonthly int) ([]models.BackupMetadata, error)
	GetSchedule(ctx context.Context) (*models.BackupSchedule, error)
	UpdateSchedule(ctx context.Context, enabled bool, cronExpr string, keepDaily, keepWeekly, keepMonthly int) (*models.BackupSchedule, error)
}
