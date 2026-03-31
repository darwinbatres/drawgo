package handler

import (
	"net/http"

	"github.com/darwinbatres/drawgo/backend/internal/config"
	"github.com/darwinbatres/drawgo/backend/internal/middleware"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/apierror"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/cookie"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/jwt"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/response"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/validate"
	"github.com/darwinbatres/drawgo/backend/internal/service"
)

// AuthHandler handles authentication HTTP endpoints.
type AuthHandler struct {
	auth       *service.AuthService
	cfg        *config.Config
	bruteForce *middleware.BruteForce
	jwt        *jwt.Manager
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(auth *service.AuthService, cfg *config.Config, bf *middleware.BruteForce, jwtMgr *jwt.Manager) *AuthHandler {
	return &AuthHandler{auth: auth, cfg: cfg, bruteForce: bf, jwt: jwtMgr}
}

// registerRequest is the request body for POST /auth/register.
type registerRequest struct {
	Email    string  `json:"email" validate:"required,email,max=255"`
	Password string  `json:"password" validate:"required,min=8,max=128,strongpassword"`
	Name     *string `json:"name" validate:"omitempty,min=1,max=100"`
}

// loginRequest is the request body for POST /auth/login.
type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// refreshRequest is the request body for POST /auth/refresh.
type refreshRequest struct {
	RefreshToken string `json:"refreshToken" validate:"omitempty"`
}

// Register handles POST /api/v1/auth/register.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if apiErr := validate.DecodeAndValidate(r, &req); apiErr != nil {
		response.Err(w, r, apiErr)
		return
	}

	user, pair, err := h.auth.Register(r.Context(), req.Email, req.Password, req.Name)
	if err != nil {
		if apiErr, ok := err.(*apierror.Error); ok {
			response.Err(w, r, apiErr)
			return
		}
		response.Err(w, r, apierror.ErrInternal)
		return
	}

	service.SetAuthCookies(w, pair, h.cfg.IsProd())
	response.Created(w, map[string]any{
		"user":   user.ToPublic(),
		"tokens": pair,
	})
}

// Login handles POST /api/v1/auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if apiErr := validate.DecodeAndValidate(r, &req); apiErr != nil {
		response.Err(w, r, apiErr)
		return
	}

	userAgent := r.UserAgent()
	ip := middleware.ExtractIP(r.RemoteAddr)

	user, pair, err := h.auth.Login(r.Context(), req.Email, req.Password, userAgent, ip)
	if err != nil {
		if h.bruteForce != nil {
			h.bruteForce.RecordFailure(ip)
		}
		if apiErr, ok := err.(*apierror.Error); ok {
			response.Err(w, r, apiErr)
			return
		}
		response.Err(w, r, apierror.ErrInternal)
		return
	}

	if h.bruteForce != nil {
		h.bruteForce.RecordSuccess(ip)
	}
	service.SetAuthCookies(w, pair, h.cfg.IsProd())
	response.JSON(w, http.StatusOK, map[string]any{
		"user":   user.ToPublic(),
		"tokens": pair,
	})
}

// Refresh handles POST /api/v1/auth/refresh.
// Accepts refresh token from cookie or request body.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	rawToken := extractRefreshToken(r)
	if rawToken == "" {
		response.Err(w, r, apierror.ErrTokenInvalid)
		return
	}

	userAgent := r.UserAgent()
	ip := middleware.ExtractIP(r.RemoteAddr)

	user, pair, err := h.auth.RefreshTokens(r.Context(), rawToken, userAgent, ip)
	if err != nil {
		if apiErr, ok := err.(*apierror.Error); ok {
			response.Err(w, r, apiErr)
			return
		}
		response.Err(w, r, apierror.ErrInternal)
		return
	}

	service.SetAuthCookies(w, pair, h.cfg.IsProd())
	response.JSON(w, http.StatusOK, map[string]any{
		"user":   user.ToPublic(),
		"tokens": pair,
	})
}

// Logout handles POST /api/v1/auth/logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserIDFromCtx(r.Context())
	if userID == "" {
		response.Err(w, r, apierror.ErrUnauthorized)
		return
	}

	// Revoke the current access token immediately via in-memory blacklist
	if accessToken := cookie.ReadAccess(r); accessToken != "" {
		h.jwt.RevokeAccessToken(accessToken)
	}

	if err := h.auth.Logout(r.Context(), userID, middleware.ExtractIP(r.RemoteAddr), r.UserAgent()); err != nil {
		if apiErr, ok := err.(*apierror.Error); ok {
			response.Err(w, r, apiErr)
			return
		}
		response.Err(w, r, apierror.ErrInternal)
		return
	}

	service.ClearAuthCookies(w, h.cfg.IsProd())
	response.NoContent(w)
}

// Me handles GET /api/v1/auth/me.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserIDFromCtx(r.Context())
	if userID == "" {
		response.Err(w, r, apierror.ErrUnauthorized)
		return
	}

	user, err := h.auth.GetUser(r.Context(), userID)
	if err != nil {
		if apiErr, ok := err.(*apierror.Error); ok {
			response.Err(w, r, apiErr)
			return
		}
		response.Err(w, r, apierror.ErrInternal)
		return
	}

	response.JSON(w, http.StatusOK, user.ToPublic())
}

// extractRefreshToken gets the refresh token from cookie or request body.
func extractRefreshToken(r *http.Request) string {
	// Try cookie first (supports __Secure- prefixed names)
	if tok := cookie.ReadRefresh(r); tok != "" {
		return tok
	}

	// Fall back to JSON body
	var req refreshRequest
	if err := validate.DecodeAndValidate(r, &req); err == nil && req.RefreshToken != "" {
		return req.RefreshToken
	}

	return ""
}
