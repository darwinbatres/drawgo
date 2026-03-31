package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"github.com/darwinbatres/drawgo/backend/internal/config"
	"github.com/darwinbatres/drawgo/backend/internal/models"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/apierror"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/jwt"
	"github.com/darwinbatres/drawgo/backend/internal/repository"
)

// OAuthUserInfo represents the normalized user info from any OAuth provider.
type OAuthUserInfo struct {
	ProviderID string
	Email      string
	Name       *string
	Image      *string
	Verified   bool
}

// OAuthService handles OAuth2 authentication flows.
type OAuthService struct {
	providers     map[string]*oauth2.Config
	users         repository.UserRepo
	accounts      repository.AccountRepo
	refreshTokens repository.RefreshTokenRepo
	audit         repository.AuditRepo
	jwt           *jwt.Manager
	log           zerolog.Logger
	isProd        bool
}

// NewOAuthService creates an OAuthService with configured providers.
func NewOAuthService(
	cfg *config.Config,
	users repository.UserRepo,
	accounts repository.AccountRepo,
	refreshTokens repository.RefreshTokenRepo,
	audit repository.AuditRepo,
	jwtManager *jwt.Manager,
	log zerolog.Logger,
) *OAuthService {
	providers := make(map[string]*oauth2.Config)

	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		providers["google"] = &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  cfg.GoogleRedirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		}
	}

	if cfg.GitHubClientID != "" && cfg.GitHubClientSecret != "" {
		providers["github"] = &oauth2.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURL:  cfg.GitHubRedirectURL,
			Scopes:       []string{"user:email", "read:user"},
			Endpoint:     github.Endpoint,
		}
	}

	return &OAuthService{
		providers:     providers,
		users:         users,
		accounts:      accounts,
		refreshTokens: refreshTokens,
		audit:         audit,
		jwt:           jwtManager,
		log:           log,
		isProd:        cfg.IsProd(),
	}
}

// GetAuthURL generates the OAuth authorization URL with a random state parameter.
func (s *OAuthService) GetAuthURL(provider string) (string, string, error) {
	cfg, ok := s.providers[provider]
	if !ok {
		return "", "", apierror.New(http.StatusBadRequest, "INVALID_PROVIDER", fmt.Sprintf("OAuth provider '%s' is not configured", provider))
	}

	state, err := generateState()
	if err != nil {
		return "", "", apierror.ErrInternal
	}

	url := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return url, state, nil
}

// HandleCallback processes the OAuth callback, exchanges the code, and returns the user + tokens.
func (s *OAuthService) HandleCallback(ctx context.Context, provider, code, userAgent, ip string) (*models.User, *TokenPair, error) {
	providerCfg, ok := s.providers[provider]
	if !ok {
		return nil, nil, apierror.New(http.StatusBadRequest, "INVALID_PROVIDER", "Invalid OAuth provider")
	}

	// Exchange authorization code for token
	oauthToken, err := providerCfg.Exchange(ctx, code)
	if err != nil {
		s.log.Error().Err(err).Str("provider", provider).Msg("oauth code exchange failed")
		return nil, nil, apierror.ErrOAuthProviderError
	}

	// Fetch user info from OAuth provider
	userInfo, err := s.fetchUserInfo(ctx, provider, providerCfg, oauthToken)
	if err != nil {
		return nil, nil, err
	}

	// Check if this OAuth account is already linked
	existingAccount, err := s.accounts.GetByProvider(ctx, provider, userInfo.ProviderID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.log.Error().Err(err).Msg("failed to check existing account")
		return nil, nil, apierror.ErrInternal
	}

	var user *models.User
	if existingAccount != nil {
		// Existing link: sign in as that user
		user, err = s.users.GetByID(ctx, existingAccount.UserID)
		if err != nil {
			s.log.Error().Err(err).Msg("failed to get user for existing account")
			return nil, nil, apierror.ErrInternal
		}
	} else {
		// No link: create or find user by email, then link the account.
		// Require a verified email before linking to an existing account to
		// prevent account takeover via unverified OAuth provider emails.
		if !userInfo.Verified {
			s.log.Warn().Str("email", userInfo.Email).Str("provider", provider).Msg("OAuth email not verified, rejecting account link")
			return nil, nil, apierror.New(http.StatusForbidden, "EMAIL_NOT_VERIFIED", "Your email must be verified by the OAuth provider before you can sign in")
		}

		user, _, err = s.users.CreateOrGetByOAuth(ctx, userInfo.Email, userInfo.Name, userInfo.Image, userInfo.Verified)
		if err != nil {
			s.log.Error().Err(err).Msg("failed to create/get user for OAuth")
			return nil, nil, apierror.ErrInternal
		}
	}

	// Upsert the OAuth account link with fresh tokens
	var accessTokenStr, refreshTokenStr *string
	at := oauthToken.AccessToken
	if at != "" {
		accessTokenStr = &at
	}
	rt := oauthToken.RefreshToken
	if rt != "" {
		refreshTokenStr = &rt
	}
	var expiresAt *int
	if !oauthToken.Expiry.IsZero() {
		v := int(oauthToken.Expiry.Unix())
		expiresAt = &v
	}

	if _, err := s.accounts.Upsert(ctx, user.ID, provider, userInfo.ProviderID, accessTokenStr, refreshTokenStr, expiresAt); err != nil {
		s.log.Error().Err(err).Msg("failed to upsert account")
		return nil, nil, apierror.ErrInternal
	}

	// Issue our JWT token pair
	pair, err := s.issueTokenPair(ctx, user, userAgent, ip)
	if err != nil {
		return nil, nil, err
	}

	// Audit
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.audit.Log(bgCtx, "", &user.ID, models.AuditActionAuthLogin, "user", user.ID, &ip, &userAgent, map[string]any{"provider": provider})
	}()

	return user, pair, nil
}

// HasProvider returns whether a given provider is configured.
func (s *OAuthService) HasProvider(provider string) bool {
	_, ok := s.providers[provider]
	return ok
}

// IsProd returns whether production mode is enabled.
func (s *OAuthService) IsProd() bool {
	return s.isProd
}

// fetchUserInfo retrieves the user's profile from the OAuth provider.
func (s *OAuthService) fetchUserInfo(ctx context.Context, provider string, cfg *oauth2.Config, token *oauth2.Token) (*OAuthUserInfo, error) {
	client := cfg.Client(ctx, token)

	switch provider {
	case "google":
		return s.fetchGoogleUserInfo(client)
	case "github":
		return s.fetchGitHubUserInfo(client)
	default:
		return nil, apierror.New(http.StatusBadRequest, "INVALID_PROVIDER", "Unsupported provider")
	}
}

func (s *OAuthService) fetchGoogleUserInfo(client *http.Client) (*OAuthUserInfo, error) {
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		s.log.Error().Err(err).Msg("google userinfo request failed")
		return nil, apierror.ErrOAuthProviderError
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, apierror.ErrOAuthProviderError
	}

	var data struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		VerifiedEmail bool   `json:"verified_email"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, apierror.ErrOAuthProviderError
	}

	info := &OAuthUserInfo{
		ProviderID: data.ID,
		Email:      data.Email,
		Verified:   data.VerifiedEmail,
	}
	if data.Name != "" {
		info.Name = &data.Name
	}
	if data.Picture != "" {
		info.Image = &data.Picture
	}
	return info, nil
}

func (s *OAuthService) fetchGitHubUserInfo(client *http.Client) (*OAuthUserInfo, error) {
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		s.log.Error().Err(err).Msg("github user request failed")
		return nil, apierror.ErrOAuthProviderError
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, apierror.ErrOAuthProviderError
	}

	var data struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, apierror.ErrOAuthProviderError
	}

	email := data.Email
	if email == "" {
		// GitHub may not return email in the user endpoint — fetch from /user/emails
		email, err = s.fetchGitHubPrimaryEmail(client)
		if err != nil {
			return nil, err
		}
	}

	info := &OAuthUserInfo{
		ProviderID: fmt.Sprintf("%d", data.ID),
		Email:      email,
		Verified:   true, // GitHub verifies emails before returning them
	}
	name := data.Name
	if name == "" {
		name = data.Login
	}
	info.Name = &name
	if data.AvatarURL != "" {
		info.Image = &data.AvatarURL
	}
	return info, nil
}

func (s *OAuthService) fetchGitHubPrimaryEmail(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", apierror.ErrOAuthProviderError
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", apierror.ErrOAuthProviderError
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", apierror.ErrOAuthProviderError
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	return "", apierror.New(http.StatusBadRequest, "NO_EMAIL", "Could not retrieve a verified email from GitHub")
}

// issueTokenPair creates JWT access + refresh tokens for the user.
func (s *OAuthService) issueTokenPair(ctx context.Context, user *models.User, userAgent, ip string) (*TokenPair, error) {
	accessToken, err := s.jwt.CreateAccessToken(user.ID, user.Email)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to create access token")
		return nil, apierror.ErrInternal
	}

	rawRefresh, err := jwt.GenerateRefreshToken()
	if err != nil {
		s.log.Error().Err(err).Msg("failed to generate refresh token")
		return nil, apierror.ErrInternal
	}

	expiresAt := time.Now().Add(s.jwt.RefreshExpiry())
	if _, err := s.refreshTokens.Create(ctx, user.ID, rawRefresh, userAgent, ip, expiresAt); err != nil {
		s.log.Error().Err(err).Msg("failed to store refresh token")
		return nil, apierror.ErrInternal
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    int(s.jwt.RefreshExpiry().Seconds()),
	}, nil
}

// generateState creates a cryptographically secure random state for CSRF protection.
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}
