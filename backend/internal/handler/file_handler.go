package handler

import (
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/darwinbatres/drawgo/backend/internal/config"
	"github.com/darwinbatres/drawgo/backend/internal/middleware"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/apierror"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/response"
	"github.com/darwinbatres/drawgo/backend/internal/service"
)

// FileHandler handles file upload/download HTTP endpoints.
type FileHandler struct {
	files       *service.FileService
	maxFileSize int64
	log         zerolog.Logger
}

// NewFileHandler creates a FileHandler.
func NewFileHandler(files *service.FileService, cfg *config.Config, log zerolog.Logger) *FileHandler {
	return &FileHandler{files: files, maxFileSize: cfg.MaxFileSize, log: log.With().Str("handler", "file").Logger()}
}

// Upload handles POST /api/v1/boards/{id}/files.
// Expects multipart form with fields: fileId, file.
func (h *FileHandler) Upload(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserIDFromCtx(r.Context())
	if userID == "" {
		response.Err(w, r, apierror.ErrUnauthorized)
		return
	}

	boardID := chi.URLParam(r, "id")
	if boardID == "" {
		response.Err(w, r, apierror.ErrBadRequest)
		return
	}

	// Parse multipart form (limit already enforced by middleware body size)
	if err := r.ParseMultipartForm(h.maxFileSize); err != nil {
		response.Err(w, r, apierror.ErrRequestTooLarge.WithMessage("Failed to parse upload"))
		return
	}

	fileID := r.FormValue("fileId")
	if fileID == "" {
		response.Err(w, r, apierror.ErrBadRequest.WithMessage("fileId is required"))
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		response.Err(w, r, apierror.ErrBadRequest.WithMessage("file is required"))
		return
	}
	defer file.Close()

	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	result, apiErr := h.files.UploadFile(r.Context(), userID, boardID, fileID, file, header.Size, contentType)
	if apiErr != nil {
		response.Err(w, r, apiErr)
		return
	}

	response.Created(w, result)
}

// Download handles GET /api/v1/boards/{id}/files/{fileId}.
// With ?presign=true, returns a presigned URL instead of streaming.
func (h *FileHandler) Download(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserIDFromCtx(r.Context())
	if userID == "" {
		response.Err(w, r, apierror.ErrUnauthorized)
		return
	}

	boardID := chi.URLParam(r, "id")
	fileID := chi.URLParam(r, "fileId")
	if boardID == "" || fileID == "" {
		response.Err(w, r, apierror.ErrBadRequest)
		return
	}

	// Presigned URL mode
	if r.URL.Query().Get("presign") == "true" {
		url, apiErr := h.files.GetPresignedURL(r.Context(), userID, boardID, fileID)
		if apiErr != nil {
			response.Err(w, r, apiErr)
			return
		}
		response.JSON(w, http.StatusOK, map[string]string{"url": url})
		return
	}

	// Stream mode
	reader, mimeType, apiErr := h.files.DownloadFile(r.Context(), userID, boardID, fileID)
	if apiErr != nil {
		response.Err(w, r, apiErr)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Cache-Control", "private, max-age=86400, immutable")
	w.Header().Set("Content-Disposition", "attachment")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, reader); err != nil {
		h.log.Error().Err(err).Str("fileId", fileID).Msg("error streaming file to client")
	}
}

// ListAssets handles GET /api/v1/boards/{id}/files.
func (h *FileHandler) ListAssets(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserIDFromCtx(r.Context())
	if userID == "" {
		response.Err(w, r, apierror.ErrUnauthorized)
		return
	}

	boardID := chi.URLParam(r, "id")
	if boardID == "" {
		response.Err(w, r, apierror.ErrBadRequest)
		return
	}

	assets, apiErr := h.files.ListAssets(r.Context(), userID, boardID)
	if apiErr != nil {
		response.Err(w, r, apiErr)
		return
	}

	response.JSON(w, http.StatusOK, assets)
}

// BoardStorage handles GET /api/v1/boards/{id}/storage.
func (h *FileHandler) BoardStorage(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserIDFromCtx(r.Context())
	if userID == "" {
		response.Err(w, r, apierror.ErrUnauthorized)
		return
	}

	boardID := chi.URLParam(r, "id")
	if boardID == "" {
		response.Err(w, r, apierror.ErrBadRequest)
		return
	}

	info, apiErr := h.files.GetBoardStorage(r.Context(), userID, boardID)
	if apiErr != nil {
		response.Err(w, r, apiErr)
		return
	}

	response.JSON(w, http.StatusOK, info)
}

// OrgStorage handles GET /api/v1/orgs/{id}/storage.
func (h *FileHandler) OrgStorage(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserIDFromCtx(r.Context())
	if userID == "" {
		response.Err(w, r, apierror.ErrUnauthorized)
		return
	}

	orgID := chi.URLParam(r, "id")
	if orgID == "" {
		response.Err(w, r, apierror.ErrBadRequest)
		return
	}

	info, apiErr := h.files.GetOrgStorage(r.Context(), userID, orgID)
	if apiErr != nil {
		response.Err(w, r, apiErr)
		return
	}

	response.JSON(w, http.StatusOK, info)
}
