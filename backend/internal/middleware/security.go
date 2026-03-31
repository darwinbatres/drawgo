package middleware

import (
	"net/http"
	"strings"
)

// Security adds security headers to all responses.
// This is a reusable middleware implementing OWASP best practices.
func Security(allowedOrigins string) func(http.Handler) http.Handler {
	// Build CSP connect-src from allowed origins
	origins := strings.Split(allowedOrigins, ",")
	connectSrc := "connect-src 'self'"
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if o != "" {
			connectSrc += " " + o
			// Also allow WebSocket variant
			connectSrc += " " + strings.Replace(strings.Replace(o, "https://", "wss://", 1), "http://", "ws://", 1)
		}
	}

	csp := strings.Join([]string{
		"default-src 'self'",
		"script-src 'self' https://esm.sh https://static.cloudflareinsights.com",
		connectSrc + " https://cloudflareinsights.com",
		"img-src 'self' data: blob:",
		"style-src 'self' 'unsafe-inline'",
		"font-src 'self' https://esm.sh",
		"frame-ancestors 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	}, "; ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			h.Set("X-XSS-Protection", "0") // CSP preferred over XSS filter
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			next.ServeHTTP(w, r)
		})
	}
}
