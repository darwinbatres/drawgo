package service

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/darwinbatres/drawgo/backend/internal/models"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/apierror"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/cookie"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/jwt"
	"github.com/darwinbatres/drawgo/backend/internal/repository"
)

// BcryptCost is the bcrypt work factor. 12 is recommended for 2026 hardware.
const BcryptCost = 12

// TokenPair holds the access and refresh tokens returned after authentication.
// RefreshToken is excluded from JSON responses — it is sent only via httpOnly cookies.
type TokenPair struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"-"`
	ExpiresIn    int    `json:"expiresIn"`
}

// AuthService handles authentication business logic.
type AuthService struct {
	users         repository.UserRepo
	refreshTokens repository.RefreshTokenRepo
	audit         repository.AuditRepo
	jwt           *jwt.Manager
	log           zerolog.Logger
}

// NewAuthService creates an AuthService.
func NewAuthService(
	users repository.UserRepo,
	refreshTokens repository.RefreshTokenRepo,
	audit repository.AuditRepo,
	jwtManager *jwt.Manager,
	log zerolog.Logger,
) *AuthService {
	return &AuthService{
		users:         users,
		refreshTokens: refreshTokens,
		audit:         audit,
		jwt:           jwtManager,
		log:           log,
	}
}

// Register creates a new user with email/password credentials.
func (s *AuthService) Register(ctx context.Context, email, password string, name *string) (*models.User, *TokenPair, error) {
	exists, err := s.users.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, nil, apierror.ErrInternal
	}
	if exists {
		return nil, nil, apierror.ErrEmailTaken
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		s.log.Error().Err(err).Msg("bcrypt hash failed")
		return nil, nil, apierror.ErrInternal
	}
	hashStr := string(hash)

	user, err := s.users.Create(ctx, email, name, &hashStr)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to create user")
		return nil, nil, apierror.ErrInternal
	}

	pair, _, err := s.issueTokenPair(ctx, user, "", "")
	if err != nil {
		return nil, nil, err
	}

	return user, pair, nil
}

// Login authenticates a user with email/password and returns tokens.
// Uses constant-time comparison to prevent user enumeration.
func (s *AuthService) Login(ctx context.Context, email, password, userAgent, ip string) (*models.User, *TokenPair, error) {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Run bcrypt anyway to prevent timing-based user enumeration
			bcrypt.CompareHashAndPassword([]byte("$2a$12$000000000000000000000000000000000000000000000000000000"), []byte(password))
			return nil, nil, apierror.ErrInvalidCredentials
		}
		s.log.Error().Err(err).Msg("failed to get user by email")
		return nil, nil, apierror.ErrInternal
	}

	if user.PasswordHash == nil {
		return nil, nil, apierror.ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(password)); err != nil {
		s.logAuditAsync(ctx, user.ID, models.AuditActionAuthFailed, "user", user.ID, &ip, &userAgent)
		return nil, nil, apierror.ErrInvalidCredentials
	}

	pair, _, err := s.issueTokenPair(ctx, user, userAgent, ip)
	if err != nil {
		return nil, nil, err
	}

	s.logAuditAsync(ctx, user.ID, models.AuditActionAuthLogin, "user", user.ID, &ip, &userAgent)

	return user, pair, nil
}

// RefreshTokens validates a refresh token and issues a new token pair (rotation).
// Implements refresh token replay detection per OWASP guidelines.
func (s *AuthService) RefreshTokens(ctx context.Context, rawRefreshToken, userAgent, ip string) (*models.User, *TokenPair, error) {
	compromised, userID, err := s.refreshTokens.IsTokenFamilyCompromised(ctx, rawRefreshToken)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to check token family")
		return nil, nil, apierror.ErrInternal
	}
	if compromised {
		s.log.Warn().Str("user_id", userID).Msg("refresh token replay detected, revoking all tokens")
		_ = s.refreshTokens.RevokeAllForUser(ctx, userID)
		return nil, nil, apierror.ErrTokenInvalid
	}

	rt, err := s.refreshTokens.GetByHash(ctx, rawRefreshToken)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, apierror.ErrTokenInvalid
		}
		s.log.Error().Err(err).Msg("failed to get refresh token")
		return nil, nil, apierror.ErrInternal
	}

	user, err := s.users.GetByID(ctx, rt.UserID)
	if err != nil {
		s.log.Error().Err(err).Str("user_id", rt.UserID).Msg("refresh token user not found")
		return nil, nil, apierror.ErrInternal
	}

	pair, newTokenID, err := s.issueTokenPair(ctx, user, userAgent, ip)
	if err != nil {
		return nil, nil, err
	}

	if err := s.refreshTokens.Rotate(ctx, rt.ID, newTokenID); err != nil {
		s.log.Error().Err(err).Msg("failed to rotate refresh token")
	}

	return user, pair, nil
}

// Logout revokes all refresh tokens for the user.
func (s *AuthService) Logout(ctx context.Context, userID, ip, userAgent string) error {
	if err := s.refreshTokens.RevokeAllForUser(ctx, userID); err != nil {
		s.log.Error().Err(err).Str("user_id", userID).Msg("failed to revoke refresh tokens")
		return apierror.ErrInternal
	}

	s.logAuditAsync(ctx, userID, models.AuditActionAuthLogout, "user", userID, &ip, &userAgent)

	return nil
}

// GetUser returns the current user by ID.
func (s *AuthService) GetUser(ctx context.Context, userID string) (*models.User, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apierror.ErrUserNotFound
		}
		return nil, apierror.ErrInternal
	}
	return user, nil
}

func (s *AuthService) issueTokenPair(ctx context.Context, user *models.User, userAgent, ip string) (*TokenPair, string, error) {
	accessToken, err := s.jwt.CreateAccessToken(user.ID, user.Email)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to create access token")
		return nil, "", apierror.ErrInternal
	}

	rawRefresh, err := jwt.GenerateRefreshToken()
	if err != nil {
		s.log.Error().Err(err).Msg("failed to generate refresh token")
		return nil, "", apierror.ErrInternal
	}

	expiresAt := time.Now().Add(s.jwt.RefreshExpiry())
	rt, err := s.refreshTokens.Create(ctx, user.ID, rawRefresh, userAgent, ip, expiresAt)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to store refresh token")
		return nil, "", apierror.ErrInternal
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    int(s.jwt.RefreshExpiry().Seconds()),
	}, rt.ID, nil
}

func (s *AuthService) logAuditAsync(ctx context.Context, actorID, action, targetType, targetID string, ip, userAgent *string) {
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.audit.Log(bgCtx, "", &actorID, action, targetType, targetID, ip, userAgent, nil); err != nil {
			s.log.Error().Err(err).Str("action", action).Msg("failed to log audit event")
		}
	}()
}

// SetAuthCookies sets httpOnly secure cookies for the access and refresh tokens.
// Uses __Host- / __Secure- prefixed names in production per RFC 6265bis.
func SetAuthCookies(w http.ResponseWriter, pair *TokenPair, secure bool) {
	cookie.SetAccess(w, pair.AccessToken, secure, 900)
	cookie.SetRefresh(w, pair.RefreshToken, secure, pair.ExpiresIn)
}

// ClearAuthCookies removes the auth cookies.
func ClearAuthCookies(w http.ResponseWriter, secure bool) {
	cookie.ClearAccess(w, secure)
	cookie.ClearRefresh(w, secure)
}
