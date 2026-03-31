package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT payload for access tokens.
type Claims struct {
	jwtv5.RegisteredClaims
	UserID string `json:"uid"`
	Email  string `json:"email"`
}

// Manager handles JWT creation and validation.
type Manager struct {
	secret        []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	blacklist     *Blacklist
}

// NewManager creates a JWT manager with the given configuration.
func NewManager(secret string, accessExpiry, refreshExpiry time.Duration) *Manager {
	return &Manager{
		secret:        []byte(secret),
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		blacklist:     NewBlacklist(accessExpiry),
	}
}

// CreateAccessToken generates a signed access token for the given user.
func (m *Manager) CreateAccessToken(userID, email string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwtv5.NewNumericDate(now),
			ExpiresAt: jwtv5.NewNumericDate(now.Add(m.accessExpiry)),
		},
		UserID: userID,
		Email:  email,
	}

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

// ValidateAccessToken parses and validates an access token, returning the claims.
// Also checks the in-memory blacklist for revoked tokens.
func (m *Manager) ValidateAccessToken(tokenStr string) (*Claims, error) {
	// Check blacklist before expensive parsing
	if m.blacklist != nil && m.blacklist.IsBlacklisted(tokenStr) {
		return nil, fmt.Errorf("token has been revoked")
	}

	token, err := jwtv5.ParseWithClaims(tokenStr, &Claims{}, func(t *jwtv5.Token) (any, error) {
		if _, ok := t.Method.(*jwtv5.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// RevokeAccessToken adds the given raw access token to the blacklist.
// The token will be rejected on subsequent validation attempts until it
// expires naturally (TTL matches the access token lifetime).
func (m *Manager) RevokeAccessToken(tokenStr string) {
	if m.blacklist != nil {
		m.blacklist.Add(tokenStr)
	}
}

// GenerateRefreshToken creates a cryptographically secure random token.
func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating refresh token: %w", err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

// RefreshExpiry returns the configured refresh token duration.
func (m *Manager) RefreshExpiry() time.Duration {
	return m.refreshExpiry
}
