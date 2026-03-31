package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/xid"

	"github.com/darwinbatres/drawgo/backend/internal/models"
)

// MembershipRepository handles membership persistence operations.
type MembershipRepository struct {
	pool *pgxpool.Pool
}

// NewMembershipRepository creates a MembershipRepository with the given connection pool.
func NewMembershipRepository(pool *pgxpool.Pool) *MembershipRepository {
	return &MembershipRepository{pool: pool}
}

// Create inserts a new membership.
func (r *MembershipRepository) Create(ctx context.Context, orgID, userID string, role models.OrgRole) (*models.Membership, error) {
	m := &models.Membership{
		ID:        xid.New().String(),
		OrgID:     orgID,
		UserID:    userID,
		Role:      role,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err := r.pool.Exec(ctx,
		`INSERT INTO memberships (id, org_id, user_id, role, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		m.ID, m.OrgID, m.UserID, m.Role, m.CreatedAt, m.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// GetByOrgAndUser retrieves the membership for a specific user in an org.
func (r *MembershipRepository) GetByOrgAndUser(ctx context.Context, orgID, userID string) (*models.Membership, error) {
	var m models.Membership
	err := r.pool.QueryRow(ctx,
		`SELECT id, org_id, user_id, role, created_at, updated_at
		 FROM memberships WHERE org_id = $1 AND user_id = $2`,
		orgID, userID,
	).Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// GetByID retrieves a membership by its ID.
func (r *MembershipRepository) GetByID(ctx context.Context, id string) (*models.Membership, error) {
	var m models.Membership
	err := r.pool.QueryRow(ctx,
		`SELECT id, org_id, user_id, role, created_at, updated_at
		 FROM memberships WHERE id = $1`, id,
	).Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ListByOrg returns all memberships for an org with user details.
func (r *MembershipRepository) ListByOrg(ctx context.Context, orgID string) ([]models.MembershipWithUser, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT m.id, m.org_id, m.user_id, m.role, m.created_at, m.updated_at,
		        u.id, u.email, u.name, u.image
		 FROM memberships m
		 JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1
		 ORDER BY m.created_at ASC`, orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []models.MembershipWithUser
	for rows.Next() {
		var mwu models.MembershipWithUser
		if err := rows.Scan(
			&mwu.ID, &mwu.OrgID, &mwu.UserID, &mwu.Role, &mwu.CreatedAt, &mwu.UpdatedAt,
			&mwu.User.ID, &mwu.User.Email, &mwu.User.Name, &mwu.User.Image,
		); err != nil {
			return nil, err
		}
		members = append(members, mwu)
	}
	return members, rows.Err()
}

// UpdateRole changes a member's role.
func (r *MembershipRepository) UpdateRole(ctx context.Context, id string, role models.OrgRole) (*models.Membership, error) {
	var m models.Membership
	err := r.pool.QueryRow(ctx,
		`UPDATE memberships SET role = $2, updated_at = $3
		 WHERE id = $1
		 RETURNING id, org_id, user_id, role, created_at, updated_at`,
		id, role, time.Now(),
	).Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Delete removes a membership by ID.
func (r *MembershipRepository) Delete(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM memberships WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete membership: %w", err)
	}
	return nil
}

// CountByUser returns the number of organizations a user belongs to.
func (r *MembershipRepository) CountByUser(ctx context.Context, userID string) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM memberships WHERE user_id = $1`, userID,
	).Scan(&count)
	return count, err
}

// Exists checks if a user is already a member of an org.
func (r *MembershipRepository) Exists(ctx context.Context, orgID, userID string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM memberships WHERE org_id = $1 AND user_id = $2)`,
		orgID, userID,
	).Scan(&exists)
	return exists, err
}

// IsOwnerOfAny returns true if the user holds the OWNER role in at least one organization.
func (r *MembershipRepository) IsOwnerOfAny(ctx context.Context, userID string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM memberships WHERE user_id = $1 AND role = 'OWNER')`,
		userID,
	).Scan(&exists)
	return exists, err
}

// CreateInTx creates a membership within an existing transaction.
func (r *MembershipRepository) CreateInTx(ctx context.Context, tx pgx.Tx, orgID, userID string, role models.OrgRole) (*models.Membership, error) {
	m := &models.Membership{
		ID:        xid.New().String(),
		OrgID:     orgID,
		UserID:    userID,
		Role:      role,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err := tx.Exec(ctx,
		`INSERT INTO memberships (id, org_id, user_id, role, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		m.ID, m.OrgID, m.UserID, m.Role, m.CreatedAt, m.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return m, nil
}
