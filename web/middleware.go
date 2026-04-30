package web

import (
	"encoding/json"
	"net/http"
)

// APIKeyMiddleware enforces X-API-Key authentication on /api/* routes
// when a key is configured. /api/health is always exempt.
func APIKeyMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health check is always unauthenticated.
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}

		// If no key is configured, skip auth entirely.
		if apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		provided := r.Header.Get("X-API-Key")
		if provided == "" {
			writeError(w, http.StatusUnauthorized, "missing X-API-Key header", "MISSING_API_KEY")
			return
		}
		if provided != apiKey {
			writeError(w, http.StatusUnauthorized, "invalid API key", "INVALID_API_KEY")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": message,
		"code":  code,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
