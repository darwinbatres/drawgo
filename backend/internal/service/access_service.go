package service

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/darwinbatres/drawgo/backend/internal/models"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/apierror"
	"github.com/darwinbatres/drawgo/backend/internal/repository"
)

// AccessService provides centralized permission checking (RBAC).
// Designed as a reusable component consumed by org, board, and share services.
type AccessService struct {
	memberships      repository.MembershipRepo
	boards           repository.BoardRepo
	boardPermissions repository.BoardPermissionRepo
}

// NewAccessService creates an AccessService.
func NewAccessService(memberships repository.MembershipRepo) *AccessService {
	return &AccessService{memberships: memberships}
}

// WithBoardRepos adds board-related repositories for board permission checks.
func (s *AccessService) WithBoardRepos(boards repository.BoardRepo, permissions repository.BoardPermissionRepo) {
	s.boards = boards
	s.boardPermissions = permissions
}

// RequireOrgRole verifies the user has at least the required role in the org.
// Returns the membership on success, or a typed API error on failure.
func (s *AccessService) RequireOrgRole(ctx context.Context, userID, orgID string, required models.OrgRole) (*models.Membership, *apierror.Error) {
	m, err := s.memberships.GetByOrgAndUser(ctx, orgID, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apierror.ErrOrgNotFound
		}
		return nil, apierror.ErrInternal
	}

	if m.Role.Level() < required.Level() {
		return nil, apierror.ErrForbidden
	}
	return m, nil
}

// HasOrgRole checks if the user meets the minimum role requirement without returning an error.
func (s *AccessService) HasOrgRole(ctx context.Context, userID, orgID string, required models.OrgRole) bool {
	m, err := s.memberships.GetByOrgAndUser(ctx, orgID, userID)
	if err != nil {
		return false
	}
	return m.Role.Level() >= required.Level()
}

// IsOrgOwner checks if the user is the OWNER of the organization.
func (s *AccessService) IsOrgOwner(ctx context.Context, userID, orgID string) bool {
	return s.HasOrgRole(ctx, userID, orgID, models.OrgRoleOwner)
}

// RequireSystemAdmin verifies the user is an OWNER of at least one organization.
// This is used to protect system-wide operations (backups, system stats, logs).
func (s *AccessService) RequireSystemAdmin(ctx context.Context, userID string) *apierror.Error {
	isOwner, err := s.memberships.IsOwnerOfAny(ctx, userID)
	if err != nil {
		return apierror.ErrInternal
	}
	if !isOwner {
		return apierror.ErrForbidden
	}
	return nil
}

// CanManageMembers checks if the user can invite/update/remove members (ADMIN+).
func (s *AccessService) CanManageMembers(ctx context.Context, userID, orgID string) bool {
	return s.HasOrgRole(ctx, userID, orgID, models.OrgRoleAdmin)
}

// GetMembership returns the user's membership in the org, or nil if not a member.
func (s *AccessService) GetMembership(ctx context.Context, userID, orgID string) *models.Membership {
	m, err := s.memberships.GetByOrgAndUser(ctx, orgID, userID)
	if err != nil {
		return nil
	}
	return m
}

// RequireBoardView verifies the user can view a board.
// Access is granted if the user is the board owner, has org VIEWER+ membership,
// or has a board-level VIEWER+ permission.
func (s *AccessService) RequireBoardView(ctx context.Context, userID, boardID string) (*models.Board, *apierror.Error) {
	board, err := s.boards.GetByID(ctx, boardID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apierror.ErrBoardNotFound
		}
		return nil, apierror.ErrInternal
	}

	if board.OwnerID == userID {
		return board, nil
	}

	// Check org-level membership (VIEWER+ can see all org boards)
	if s.HasOrgRole(ctx, userID, board.OrgID, models.OrgRoleViewer) {
		return board, nil
	}

	// Check board-level permission
	if s.hasBoardPermission(ctx, boardID, userID, models.BoardRoleViewer) {
		return board, nil
	}

	return nil, apierror.ErrBoardNotFound
}

// RequireBoardEdit verifies the user can edit a board.
// Access is granted if the user is the board owner, has org ADMIN+ membership,
// or has a board-level EDITOR+ permission.
func (s *AccessService) RequireBoardEdit(ctx context.Context, userID, boardID string) (*models.Board, *apierror.Error) {
	board, err := s.boards.GetByID(ctx, boardID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apierror.ErrBoardNotFound
		}
		return nil, apierror.ErrInternal
	}

	if board.OwnerID == userID {
		return board, nil
	}

	// Org ADMIN+ can edit any board in the org
	if s.HasOrgRole(ctx, userID, board.OrgID, models.OrgRoleAdmin) {
		return board, nil
	}

	// Check board-level EDITOR+ permission
	if s.hasBoardPermission(ctx, boardID, userID, models.BoardRoleEditor) {
		return board, nil
	}

	return nil, apierror.ErrForbidden
}

// RequireBoardDelete verifies the user can delete a board.
// Only the board owner or org OWNER can delete boards.
func (s *AccessService) RequireBoardDelete(ctx context.Context, userID, boardID string) (*models.Board, *apierror.Error) {
	board, err := s.boards.GetByID(ctx, boardID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apierror.ErrBoardNotFound
		}
		return nil, apierror.ErrInternal
	}

	if board.OwnerID == userID {
		return board, nil
	}

	if s.IsOrgOwner(ctx, userID, board.OrgID) {
		return board, nil
	}

	return nil, apierror.ErrForbidden
}

// hasBoardPermission checks if the user has at least the required board role.
func (s *AccessService) hasBoardPermission(ctx context.Context, boardID, userID string, required models.BoardRole) bool {
	if s.boardPermissions == nil {
		return false
	}
	bp, err := s.boardPermissions.GetByBoardAndUser(ctx, boardID, userID)
	if err != nil {
		return false
	}
	return bp.Role.Level() >= required.Level()
}
