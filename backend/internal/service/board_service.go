package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/darwinbatres/drawgo/backend/internal/models"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/apierror"
	"github.com/darwinbatres/drawgo/backend/internal/repository"
)

const maxSearchContentLength = 50000

// BoardService handles board and version business logic.
type BoardService struct {
	pool        *pgxpool.Pool
	boards      repository.BoardRepo
	versions    repository.BoardVersionRepo
	audit       repository.AuditRepo
	access      *AccessService
	files       *FileService
	log         zerolog.Logger
	maxVersions int
}

// NewBoardService creates a BoardService.
func NewBoardService(
	pool *pgxpool.Pool,
	boards repository.BoardRepo,
	versions repository.BoardVersionRepo,
	audit repository.AuditRepo,
	access *AccessService,
	log zerolog.Logger,
	maxVersions int,
) *BoardService {
	return &BoardService{
		pool:        pool,
		boards:      boards,
		versions:    versions,
		audit:       audit,
		access:      access,
		log:         log,
		maxVersions: maxVersions,
	}
}

// SetFileService sets the file service for image mirroring (breaks circular init dependency).
func (s *BoardService) SetFileService(files *FileService) {
	s.files = files
}

// CreateBoardInput contains the parameters for creating a board.
type CreateBoardInput struct {
	OrgID        string          `json:"orgId"`
	OwnerID      string          `json:"ownerId"`
	Title        string          `json:"title"`
	Description  *string         `json:"description,omitempty"`
	Tags         []string        `json:"tags,omitempty"`
	SceneJSON    json.RawMessage `json:"sceneJson"`
	AppStateJSON json.RawMessage `json:"appStateJson,omitempty"`
}

// SaveVersionInput contains the parameters for saving a new version.
type SaveVersionInput struct {
	BoardID      string          `json:"boardId"`
	UserID       string          `json:"userId"`
	SceneJSON    json.RawMessage `json:"sceneJson"`
	AppStateJSON json.RawMessage `json:"appStateJson,omitempty"`
	Label        *string         `json:"label,omitempty"`
	ExpectedEtag *string         `json:"expectedEtag,omitempty"`
	Thumbnail    *string         `json:"thumbnail,omitempty"`
}

// SaveVersionResult is the outcome of a version save operation.
type SaveVersionResult struct {
	Conflict    bool                `json:"conflict"`
	CurrentEtag string              `json:"currentEtag,omitempty"`
	Version     *models.BoardVersion `json:"version,omitempty"`
	Etag        string              `json:"etag,omitempty"`
}

// UpdateBoardInput contains optional metadata fields to update.
type UpdateBoardInput struct {
	Title       *string  `json:"title,omitempty"`
	Description *string  `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	IsArchived  *bool    `json:"isArchived,omitempty"`
}

// CreateBoard creates a new board with an initial version in a transaction.
func (s *BoardService) CreateBoard(ctx context.Context, userID string, input CreateBoardInput) (*models.Board, *apierror.Error) {
	// Require MEMBER+ in the org to create boards
	if _, apiErr := s.access.RequireOrgRole(ctx, userID, input.OrgID, models.OrgRoleMember); apiErr != nil {
		return nil, apiErr
	}

	searchContent := extractSearchableContent(input.SceneJSON)
	etag := generateEtag(input.OrgID)

	tags := input.Tags
	if tags == nil {
		tags = []string{}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to begin transaction")
		return nil, apierror.ErrInternal
	}
	defer tx.Rollback(ctx)

	board := &models.Board{
		OrgID:         input.OrgID,
		OwnerID:       userID,
		Title:         input.Title,
		Description:   input.Description,
		Tags:          tags,
		VersionNumber: 1,
		Etag:          etag,
		SearchContent: strPtr(searchContent),
	}

	if err := s.boards.CreateInTx(ctx, tx, board); err != nil {
		s.log.Error().Err(err).Msg("failed to create board")
		return nil, apierror.ErrInternal
	}

	version := &models.BoardVersion{
		BoardID:      board.ID,
		Version:      1,
		CreatedByID:  userID,
		SceneJSON:    input.SceneJSON,
		AppStateJSON: input.AppStateJSON,
	}

	if err := s.versions.CreateInTx(ctx, tx, version); err != nil {
		s.log.Error().Err(err).Msg("failed to create initial version")
		return nil, apierror.ErrInternal
	}

	if err := s.boards.UpdateVersionInfoInTx(ctx, tx, board.ID, version.ID, etag, 1, board.SearchContent, nil); err != nil {
		s.log.Error().Err(err).Msg("failed to update board version info")
		return nil, apierror.ErrInternal
	}

	if err := tx.Commit(ctx); err != nil {
		s.log.Error().Err(err).Msg("failed to commit board creation")
		return nil, apierror.ErrInternal
	}

	board.CurrentVersionID = &version.ID
	s.logAuditAsync(userID, board.OrgID, models.AuditActionBoardCreate, "board", board.ID)

	return board, nil
}

// GetBoard retrieves a board with its latest version. Requires VIEWER+ access.
func (s *BoardService) GetBoard(ctx context.Context, userID, boardID string) (*models.BoardWithVersion, *apierror.Error) {
	if _, apiErr := s.access.RequireBoardView(ctx, userID, boardID); apiErr != nil {
		return nil, apiErr
	}

	bv, err := s.boards.GetByIDWithVersion(ctx, boardID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apierror.ErrBoardNotFound
		}
		s.log.Error().Err(err).Msg("failed to get board with version")
		return nil, apierror.ErrInternal
	}

	return bv, nil
}

// UpdateBoard updates board metadata. Requires EDITOR+ access.
func (s *BoardService) UpdateBoard(ctx context.Context, userID, boardID string, input UpdateBoardInput) (*models.Board, *apierror.Error) {
	board, apiErr := s.access.RequireBoardEdit(ctx, userID, boardID)
	if apiErr != nil {
		return nil, apiErr
	}

	if input.Title != nil {
		board.Title = *input.Title
	}
	if input.Description != nil {
		board.Description = input.Description
	}
	if input.Tags != nil {
		board.Tags = input.Tags
	}
	if input.IsArchived != nil {
		board.IsArchived = *input.IsArchived
	}

	if err := s.boards.Update(ctx, board); err != nil {
		s.log.Error().Err(err).Msg("failed to update board")
		return nil, apierror.ErrInternal
	}

	action := models.AuditActionBoardUpdate
	if input.IsArchived != nil {
		if *input.IsArchived {
			action = models.AuditActionBoardArchive
		} else {
			action = models.AuditActionBoardUpdate
		}
	}
	s.logAuditAsync(userID, board.OrgID, action, "board", boardID)

	return board, nil
}

// DeleteBoard permanently removes a board. Requires DELETE permission.
func (s *BoardService) DeleteBoard(ctx context.Context, userID, boardID string) *apierror.Error {
	board, apiErr := s.access.RequireBoardDelete(ctx, userID, boardID)
	if apiErr != nil {
		return apiErr
	}

	if err := s.boards.Delete(ctx, boardID); err != nil {
		s.log.Error().Err(err).Msg("failed to delete board")
		return apierror.ErrInternal
	}

	s.logAuditAsync(userID, board.OrgID, models.AuditActionBoardDelete, "board", boardID)
	return nil
}

// SaveVersion saves a new board version with optimistic concurrency control.
func (s *BoardService) SaveVersion(ctx context.Context, input SaveVersionInput) (*SaveVersionResult, *apierror.Error) {
	if _, apiErr := s.access.RequireBoardEdit(ctx, input.UserID, input.BoardID); apiErr != nil {
		return nil, apiErr
	}

	cleanedScene := cleanOrphanedFiles(input.SceneJSON)
	searchContent := extractSearchableContent(cleanedScene)

	// Compact the scene for storage: strip deleted elements to minimize
	// database bloat. File binary data is preserved for frontend rendering.
	compactedScene := compactSceneForStorage(cleanedScene)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to begin transaction")
		return nil, apierror.ErrInternal
	}
	defer tx.Rollback(ctx)

	board, err := s.boards.GetByIDForUpdate(ctx, tx, input.BoardID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apierror.ErrBoardNotFound
		}
		s.log.Error().Err(err).Msg("failed to get board for update")
		return nil, apierror.ErrInternal
	}

	// Optimistic concurrency check
	if input.ExpectedEtag != nil && board.Etag != *input.ExpectedEtag {
		return &SaveVersionResult{
			Conflict:    true,
			CurrentEtag: board.Etag,
		}, nil
	}

	newVersionNum := board.VersionNumber + 1
	newEtag := generateEtag(input.BoardID)

	version := &models.BoardVersion{
		BoardID:      input.BoardID,
		Version:      newVersionNum,
		CreatedByID:  input.UserID,
		Label:        input.Label,
		SceneJSON:    compactedScene,
		AppStateJSON: input.AppStateJSON,
		ThumbnailURL: input.Thumbnail,
	}

	if err := s.versions.CreateInTx(ctx, tx, version); err != nil {
		s.log.Error().Err(err).Msg("failed to create version")
		return nil, apierror.ErrInternal
	}

	sc := strPtr(searchContent)
	if err := s.boards.UpdateVersionInfoInTx(ctx, tx, input.BoardID, version.ID, newEtag, newVersionNum, sc, input.Thumbnail); err != nil {
		s.log.Error().Err(err).Msg("failed to update board version info")
		return nil, apierror.ErrInternal
	}

	if err := tx.Commit(ctx); err != nil {
		s.log.Error().Err(err).Msg("failed to commit version save")
		return nil, apierror.ErrInternal
	}

	s.logAuditAsync(input.UserID, board.OrgID, models.AuditActionVersionCreate, "board_version", version.ID)

	// Mirror images to S3 in the background for metrics and backup
	if s.files != nil {
		go s.files.MirrorImagesToS3(context.Background(), input.BoardID, cleanedScene)
	}

	// Prune old versions in the background (non-blocking)
	if s.maxVersions > 0 {
		go func() {
			pruned, err := s.versions.PruneOldVersions(context.Background(), input.BoardID, s.maxVersions)
			if err != nil {
				s.log.Error().Err(err).Str("boardId", input.BoardID).Msg("failed to prune old versions")
			} else if pruned > 0 {
				s.log.Info().Int64("pruned", pruned).Str("boardId", input.BoardID).Msg("pruned old board versions")
			}
		}()
	}

	return &SaveVersionResult{
		Version: version,
		Etag:    newEtag,
	}, nil
}

// ListVersions returns paginated version history for a board. Requires VIEWER+ access.
func (s *BoardService) ListVersions(ctx context.Context, userID, boardID string, limit, offset int) ([]repository.BoardVersionWithCreator, int64, *apierror.Error) {
	if _, apiErr := s.access.RequireBoardView(ctx, userID, boardID); apiErr != nil {
		return nil, 0, apiErr
	}

	versions, total, err := s.versions.ListByBoard(ctx, boardID, limit, offset)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to list versions")
		return nil, 0, apierror.ErrInternal
	}

	return versions, total, nil
}

// GetVersion retrieves a specific version. Requires VIEWER+ access.
func (s *BoardService) GetVersion(ctx context.Context, userID, boardID string, versionNum int) (*models.BoardVersion, *apierror.Error) {
	if _, apiErr := s.access.RequireBoardView(ctx, userID, boardID); apiErr != nil {
		return nil, apiErr
	}

	v, err := s.versions.GetByBoardAndVersion(ctx, boardID, versionNum)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apierror.ErrVersionNotFound
		}
		s.log.Error().Err(err).Msg("failed to get version")
		return nil, apierror.ErrInternal
	}

	return v, nil
}

// RestoreVersion creates a new version from an old version's content. Requires EDITOR+ access.
func (s *BoardService) RestoreVersion(ctx context.Context, userID, boardID string, versionNum int) (*SaveVersionResult, *apierror.Error) {
	oldVersion, err := s.versions.GetByBoardAndVersion(ctx, boardID, versionNum)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apierror.ErrVersionNotFound
		}
		s.log.Error().Err(err).Msg("failed to get version for restore")
		return nil, apierror.ErrInternal
	}

	label := fmt.Sprintf("Restored from v%d", versionNum)
	result, apiErr := s.SaveVersion(ctx, SaveVersionInput{
		BoardID:      boardID,
		UserID:       userID,
		SceneJSON:    oldVersion.SceneJSON,
		AppStateJSON: oldVersion.AppStateJSON,
		Label:        &label,
	})
	if apiErr != nil {
		return nil, apiErr
	}

	if result.Version != nil {
		s.logAuditAsync(userID, "", models.AuditActionVersionRestore, "board_version", result.Version.ID)
	}

	return result, nil
}

// SearchBoards searches boards in an org. Requires VIEWER+ in the org.
func (s *BoardService) SearchBoards(ctx context.Context, userID string, params repository.BoardSearchParams) (*repository.BoardSearchResult, *apierror.Error) {
	if _, apiErr := s.access.RequireOrgRole(ctx, userID, params.OrgID, models.OrgRoleViewer); apiErr != nil {
		return nil, apiErr
	}

	result, err := s.boards.Search(ctx, params)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to search boards")
		return nil, apierror.ErrInternal
	}

	return result, nil
}

func (s *BoardService) logAuditAsync(actorID, orgID, action, targetType, targetID string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.audit.Log(ctx, orgID, &actorID, action, targetType, targetID, nil, nil, nil); err != nil {
			s.log.Error().Err(err).Str("action", action).Msg("failed to log audit event")
		}
	}()
}

// --- Search content extraction helpers ---

// sceneElement is the Go representation of an Excalidraw element for search extraction.
type sceneElement struct {
	Type       string       `json:"type"`
	Text       string       `json:"text,omitempty"`
	IsDeleted  bool         `json:"isDeleted,omitempty"`
	CustomData *customData  `json:"customData,omitempty"`
}

type customData struct {
	Markdown              string `json:"markdown,omitempty"`
	RichTextContent       string `json:"richTextContent,omitempty"`
	IsMarkdownCard        bool   `json:"isMarkdownCard,omitempty"`
	IsRichTextCard        bool   `json:"isRichTextCard,omitempty"`
	IsMarkdownSearchText  bool   `json:"isMarkdownSearchText,omitempty"`
	IsRichTextSearchText  bool   `json:"isRichTextSearchText,omitempty"`
}

type sceneData struct {
	Elements []sceneElement         `json:"elements"`
	Files    map[string]interface{} `json:"files,omitempty"`
}

// extractSearchableContent extracts plain text from all scene elements for FTS.
func extractSearchableContent(sceneJSON json.RawMessage) string {
	if len(sceneJSON) == 0 {
		return ""
	}

	var scene sceneData
	if err := json.Unmarshal(sceneJSON, &scene); err != nil {
		return ""
	}

	var parts []string
	for _, el := range scene.Elements {
		if el.IsDeleted {
			continue
		}
		// Skip search text elements (they duplicate card content)
		if el.CustomData != nil && (el.CustomData.IsMarkdownSearchText || el.CustomData.IsRichTextSearchText) {
			continue
		}

		// Regular text elements
		if el.Type == "text" && el.Text != "" {
			parts = append(parts, el.Text)
		}

		// Markdown cards
		if el.CustomData != nil && el.CustomData.IsMarkdownCard && el.CustomData.Markdown != "" {
			if plain := stripMarkdownToPlainText(el.CustomData.Markdown); plain != "" {
				parts = append(parts, plain)
			}
		}

		// Rich text cards
		if el.CustomData != nil && el.CustomData.IsRichTextCard && el.CustomData.RichTextContent != "" {
			var node tiptapNode
			if err := json.Unmarshal([]byte(el.CustomData.RichTextContent), &node); err == nil {
				if plain := extractTextFromTiptapJSON(node); plain != "" {
					parts = append(parts, plain)
				}
			}
		}
	}

	fullText := strings.Join(parts, " ")
	fullText = collapseWhitespace(fullText)

	if len(fullText) > maxSearchContentLength {
		fullText = fullText[:maxSearchContentLength]
	}

	return fullText
}

var (
	reCodeBlock   = regexp.MustCompile("(?s)```.*?```")
	reInlineCode  = regexp.MustCompile("`[^`]+`")
	reHeaders     = regexp.MustCompile(`(?m)^#{1,6}\s+`)
	reBold        = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	reItalic      = regexp.MustCompile(`\*([^*]+)\*`)
	reBoldU       = regexp.MustCompile(`__([^_]+)__`)
	reItalicU     = regexp.MustCompile(`_([^_]+)_`)
	reLinks       = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`)
	reImages      = regexp.MustCompile(`!\[([^\]]*)\]\([^)]+\)`)
	reHR          = regexp.MustCompile(`(?m)^[-*_]{3,}\s*$`)
	reUnordList   = regexp.MustCompile(`(?m)^[\s]*[-*+]\s+`)
	reOrdList     = regexp.MustCompile(`(?m)^[\s]*\d+\.\s+`)
	reBlockquote  = regexp.MustCompile(`(?m)^>\s+`)
	reMultiNewline = regexp.MustCompile(`\n{3,}`)
	reWhitespace  = regexp.MustCompile(`\s+`)
)

// stripMarkdownToPlainText removes markdown syntax, preserving readable text.
func stripMarkdownToPlainText(md string) string {
	s := reCodeBlock.ReplaceAllString(md, "")
	s = reInlineCode.ReplaceAllString(s, "")
	s = reHeaders.ReplaceAllString(s, "")
	s = reBold.ReplaceAllString(s, "$1")
	s = reItalic.ReplaceAllString(s, "$1")
	s = reBoldU.ReplaceAllString(s, "$1")
	s = reItalicU.ReplaceAllString(s, "$1")
	s = reImages.ReplaceAllString(s, "$1")
	s = reLinks.ReplaceAllString(s, "$1")
	s = reHR.ReplaceAllString(s, "")
	s = reUnordList.ReplaceAllString(s, "")
	s = reOrdList.ReplaceAllString(s, "")
	s = reBlockquote.ReplaceAllString(s, "")
	s = reMultiNewline.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

type tiptapNode struct {
	Type    string       `json:"type,omitempty"`
	Text    string       `json:"text,omitempty"`
	Content []tiptapNode `json:"content,omitempty"`
}

// extractTextFromTiptapJSON recursively extracts plain text from Tiptap JSON.
func extractTextFromTiptapJSON(node tiptapNode) string {
	if node.Text != "" {
		return node.Text
	}
	var parts []string
	for _, child := range node.Content {
		if t := extractTextFromTiptapJSON(child); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, " ")
}

// cleanOrphanedFiles removes files not referenced by any image element.
func cleanOrphanedFiles(sceneJSON json.RawMessage) json.RawMessage {
	if len(sceneJSON) == 0 {
		return sceneJSON
	}

	// Use a generic representation so we don't lose any element properties.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(sceneJSON, &raw); err != nil {
		return sceneJSON
	}

	filesRaw, ok := raw["files"]
	if !ok {
		return sceneJSON
	}
	var files map[string]json.RawMessage
	if err := json.Unmarshal(filesRaw, &files); err != nil || len(files) == 0 {
		return sceneJSON
	}

	// Collect referenced file IDs from image elements
	usedFileIDs := make(map[string]struct{})
	type elementWithFileID struct {
		Type   string `json:"type"`
		FileID string `json:"fileId,omitempty"`
	}
	if elemRaw, ok := raw["elements"]; ok {
		var elements []elementWithFileID
		if err := json.Unmarshal(elemRaw, &elements); err == nil {
			for _, el := range elements {
				if el.Type == "image" && el.FileID != "" {
					usedFileIDs[el.FileID] = struct{}{}
				}
			}
		}
	}

	// Remove orphaned files
	changed := false
	for fileID := range files {
		if _, ok := usedFileIDs[fileID]; !ok {
			delete(files, fileID)
			changed = true
		}
	}

	if !changed {
		return sceneJSON
	}

	// Marshal cleaned files back and update the scene
	cleanedFiles, err := json.Marshal(files)
	if err != nil {
		return sceneJSON
	}
	raw["files"] = cleanedFiles

	cleaned, err := json.Marshal(raw)
	if err != nil {
		return sceneJSON
	}
	return cleaned
}

// compactSceneForStorage strips deleted elements from the scene JSON before
// persisting a version. This reduces database bloat from accumulated
// soft-deleted elements. File binary data (dataURL) is intentionally
// preserved because the frontend needs it to render images immediately.
func compactSceneForStorage(sceneJSON json.RawMessage) json.RawMessage {
	if len(sceneJSON) == 0 {
		return sceneJSON
	}

	// Use a generic representation so we don't lose unknown fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(sceneJSON, &raw); err != nil {
		return sceneJSON
	}

	changed := false

	// --- Strip deleted elements ---
	if elemRaw, ok := raw["elements"]; ok {
		var elements []map[string]interface{}
		if err := json.Unmarshal(elemRaw, &elements); err == nil {
			kept := make([]map[string]interface{}, 0, len(elements))
			for _, el := range elements {
				if del, ok := el["isDeleted"].(bool); ok && del {
					changed = true
					continue
				}
				kept = append(kept, el)
			}
			if changed {
				if b, err := json.Marshal(kept); err == nil {
					raw["elements"] = b
				}
			}
		}
	}

	// NOTE: We intentionally keep file binary data (dataURL) in the stored
	// scene. The frontend needs dataURL to render images immediately on load.
	// PostgreSQL TOAST compression handles large JSONB values transparently.
	// The deleted-element stripping above is the main space saver.

	if !changed {
		return sceneJSON
	}

	compacted, err := json.Marshal(raw)
	if err != nil {
		return sceneJSON
	}
	return compacted
}

// generateEtag creates a unique etag for optimistic concurrency.
func generateEtag(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().UnixMilli(), hex.EncodeToString(b))
}

func collapseWhitespace(s string) string {
	return strings.TrimSpace(reWhitespace.ReplaceAllString(s, " "))
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
