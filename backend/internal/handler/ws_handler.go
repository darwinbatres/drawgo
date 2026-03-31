package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/darwinbatres/drawgo/backend/internal/config"
	"github.com/darwinbatres/drawgo/backend/internal/middleware"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/apierror"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/cookie"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/jwt"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/response"
	"github.com/darwinbatres/drawgo/backend/internal/realtime"
	"github.com/darwinbatres/drawgo/backend/internal/service"
)

// WSHandler handles WebSocket upgrade requests for real-time board collaboration.
type WSHandler struct {
	hub        *realtime.Hub
	jwtManager *jwt.Manager
	shares     *service.ShareService
	access     *service.AccessService
	log        zerolog.Logger
	origins    []string
	cfg        *config.Config
}

// NewWSHandler creates a WSHandler.
func NewWSHandler(
	hub *realtime.Hub,
	jwtManager *jwt.Manager,
	shares *service.ShareService,
	access *service.AccessService,
	log zerolog.Logger,
	origins []string,
	cfg *config.Config,
) *WSHandler {
	return &WSHandler{
		hub:        hub,
		jwtManager: jwtManager,
		shares:     shares,
		access:     access,
		log:        log.With().Str("handler", "ws").Logger(),
		origins:    origins,
		cfg:        cfg,
	}
}

// Upgrade handles GET /api/v1/ws/boards/{id} — upgrades HTTP to WebSocket.
// Authentication is via query params: ?token=<jwt> or ?share=<shareToken>.
func (h *WSHandler) Upgrade(w http.ResponseWriter, r *http.Request) {
	boardID := chi.URLParam(r, "id")
	if boardID == "" {
		response.Err(w, r, apierror.ErrBadRequest)
		return
	}

	// Authenticate: JWT token or share token from query params
	info, apiErr := h.authenticate(r, boardID)
	if apiErr != nil {
		response.Err(w, r, apiErr)
		return
	}

	// Check room capacity
	room := h.hub.GetOrCreateRoom(boardID)
	if room.IsFull() {
		response.Err(w, r, apierror.ErrBadRequest.WithMessage("Board room is full"))
		return
	}

	// Accept WebSocket upgrade
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: h.origins,
	})
	if err != nil {
		h.log.Error().Err(err).Msg("websocket upgrade failed")
		return
	}

	// Assign cursor color
	info.Color = room.NextColor()
	info.JoinedAt = time.Now().UnixMilli()

	client := realtime.NewClient(conn, room, *info, realtime.ClientConfig{
		MaxMessageSize: h.cfg.WSMaxMessageSize,
		WriteTimeout:   h.cfg.WSWriteTimeout,
	}, h.log)

	room.Join(client)
	// Use a detached context so the API timeout middleware doesn't kill the
	// long-lived WebSocket connection after APIReadTimeout seconds.
	client.Run(context.Background())
}

// Stats handles GET /api/v1/ws/stats — returns hub statistics.
func (h *WSHandler) Stats(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserIDFromCtx(r.Context())
	if userID == "" {
		response.Err(w, r, apierror.ErrUnauthorized)
		return
	}

	response.JSON(w, http.StatusOK, h.hub.Stats())
}

// authenticate validates the connection request using JWT or share token.
// Preference order: httpOnly cookie (most secure) → query param JWT → share token.
func (h *WSHandler) authenticate(r *http.Request, boardID string) (*realtime.ViewerInfo, *apierror.Error) {
	q := r.URL.Query()

	// Try JWT from httpOnly cookie first (browser WS requests carry cookies)
	// This is preferred because cookies are not exposed in URLs/logs.
	if tok := cookie.ReadAccess(r); tok != "" {
		return h.authWithJWT(r.Context(), tok, boardID)
	}

	// Fall back to JWT from query param (for non-browser clients)
	if tok := q.Get("token"); tok != "" {
		return h.authWithJWT(r.Context(), tok, boardID)
	}

	// Try share token
	if shareTok := q.Get("share"); shareTok != "" {
		return h.authWithShareToken(r.Context(), shareTok, boardID)
	}

	return nil, apierror.ErrUnauthorized.WithMessage("Missing token or share parameter")
}

// authWithJWT validates a JWT and checks board access.
func (h *WSHandler) authWithJWT(ctx context.Context, tokenStr, boardID string) (*realtime.ViewerInfo, *apierror.Error) {
	claims, err := h.jwtManager.ValidateAccessToken(tokenStr)
	if err != nil {
		return nil, apierror.ErrTokenInvalid
	}

	// Verify user can at least view the board
	_, apiErr := h.access.RequireBoardView(ctx, claims.UserID, boardID)
	if apiErr != nil {
		return nil, apiErr
	}

	return &realtime.ViewerInfo{
		UserID: claims.UserID,
		Name:   claims.Email,
		Role:   "authenticated",
		IsAnon: false,
	}, nil
}

// authWithShareToken validates a share token and checks it's for the correct board.
func (h *WSHandler) authWithShareToken(ctx context.Context, shareTok, boardID string) (*realtime.ViewerInfo, *apierror.Error) {
	link, valid := h.shares.ValidateShareToken(ctx, shareTok)
	if !valid || link == nil {
		return nil, apierror.ErrUnauthorized.WithMessage("Invalid share token")
	}

	// Ensure the share token is for this board
	if link.BoardID != boardID {
		return nil, apierror.ErrForbidden.WithMessage("Share token is not for this board")
	}

	return &realtime.ViewerInfo{
		UserID: "anon-" + link.ID[:8],
		Name:   "Anonymous",
		Role:   string(link.Role),
		IsAnon: true,
	}, nil
}
