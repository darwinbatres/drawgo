package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/darwinbatres/drawgo/backend/internal/config"
	"github.com/darwinbatres/drawgo/backend/internal/handler"
	"github.com/darwinbatres/drawgo/backend/internal/models"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/jwt"
	"github.com/darwinbatres/drawgo/backend/internal/service"
	"github.com/darwinbatres/drawgo/backend/internal/testutil"
	"github.com/darwinbatres/drawgo/backend/internal/testutil/mocks"
)

type authHandlerEnv struct {
	handler    *handler.AuthHandler
	userRepo   *mocks.MockUserRepo
	refreshRepo *mocks.MockRefreshTokenRepo
	auditRepo  *mocks.MockAuditRepo
	jwtMgr     *jwt.Manager
}

func newAuthHandlerEnv(t *testing.T) *authHandlerEnv {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepo(ctrl)
	refreshRepo := mocks.NewMockRefreshTokenRepo(ctrl)
	auditRepo := mocks.NewMockAuditRepo(ctrl)

	jwtMgr := jwt.NewManager("test-secret-key-32chars-minimum!", 15*time.Minute, 720*time.Hour)

	authSvc := service.NewAuthService(userRepo, refreshRepo, auditRepo, jwtMgr, testutil.NopLogger())
	cfg := &config.Config{Env: "development"}
	h := handler.NewAuthHandler(authSvc, cfg, nil, jwtMgr)

	return &authHandlerEnv{
		handler:    h,
		userRepo:   userRepo,
		refreshRepo: refreshRepo,
		auditRepo:  auditRepo,
		jwtMgr:     jwtMgr,
	}
}

// --- Register ---

func TestAuthHandler_Register_Success(t *testing.T) {
	env := newAuthHandlerEnv(t)

	env.userRepo.EXPECT().ExistsByEmail(gomock.Any(), "new@test.com").Return(false, nil)
	env.userRepo.EXPECT().Create(gomock.Any(), "new@test.com", gomock.Any(), gomock.Any()).Return(&models.User{
		ID: "user-new", Email: "new@test.com",
	}, nil)
	env.refreshRepo.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&models.RefreshToken{ID: "rt-1"}, nil)
	env.auditRepo.EXPECT().Log(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	body := `{"email":"new@test.com","password":"securePass123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Register(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	var respBody map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&respBody))
	data := respBody["data"].(map[string]any)
	assert.Contains(t, data, "user")
	assert.Contains(t, data, "tokens")
}

func TestAuthHandler_Register_InvalidEmail(t *testing.T) {
	env := newAuthHandlerEnv(t)

	body := `{"email":"not-valid","password":"securePass123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Register(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestAuthHandler_Register_ShortPassword(t *testing.T) {
	env := newAuthHandlerEnv(t)

	body := `{"email":"test@test.com","password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Register(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestAuthHandler_Register_DuplicateEmail(t *testing.T) {
	env := newAuthHandlerEnv(t)

	env.userRepo.EXPECT().ExistsByEmail(gomock.Any(), "dupe@test.com").Return(true, nil)

	body := `{"email":"dupe@test.com","password":"securePass123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Register(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestAuthHandler_Register_MissingFields(t *testing.T) {
	env := newAuthHandlerEnv(t)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Register(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// --- Login ---

func TestAuthHandler_Login_InvalidBody(t *testing.T) {
	env := newAuthHandlerEnv(t)

	body := `{"email":"","password":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Login(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestAuthHandler_Login_MissingFields(t *testing.T) {
	env := newAuthHandlerEnv(t)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Login(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// --- Logout ---

func TestAuthHandler_Logout_Unauthorized(t *testing.T) {
	env := newAuthHandlerEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	rec := httptest.NewRecorder()

	env.handler.Logout(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- Me ---

func TestAuthHandler_Me_Unauthorized(t *testing.T) {
	env := newAuthHandlerEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	rec := httptest.NewRecorder()

	env.handler.Me(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthHandler_Me_Success(t *testing.T) {
	env := newAuthHandlerEnv(t)

	name := "Test User"
	env.userRepo.EXPECT().GetByID(gomock.Any(), "user-1").Return(&models.User{
		ID: "user-1", Email: "user@test.com", Name: &name,
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req = withUserID(req, "user-1")
	rec := httptest.NewRecorder()

	env.handler.Me(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var respBody map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&respBody))
	data := respBody["data"].(map[string]any)
	assert.Equal(t, "user@test.com", data["email"])
	assert.Equal(t, "Test User", data["name"])
}

// --- Refresh ---

func TestAuthHandler_Refresh_NoToken(t *testing.T) {
	env := newAuthHandlerEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Refresh(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
