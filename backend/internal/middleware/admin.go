package middleware

import (
	"context"
	"net/http"

	"github.com/darwinbatres/drawgo/backend/internal/pkg/apierror"
	"github.com/darwinbatres/drawgo/backend/internal/pkg/response"
)

// AdminCheckFunc is a function that returns nil if the user is a system admin.
type AdminCheckFunc func(ctx context.Context, userID string) *apierror.Error

// AdminOnly creates middleware that restricts access to system administrators.
// The check function is called with the authenticated user's ID (from context)
// and should return nil to allow access or an apierror to reject.
func AdminOnly(check AdminCheckFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := UserIDFromCtx(r.Context())
			if userID == "" {
				response.Err(w, r, apierror.ErrUnauthorized)
				return
			}

			if apiErr := check(r.Context(), userID); apiErr != nil {
				response.Err(w, r, apiErr)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
