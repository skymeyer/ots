package backend

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/rs/zerolog/log"
	"github.com/skymeyer/onetime-secret/frontend"
	"github.com/thomaspoignant/go-feature-flag/ffcontext"
)

// StartServer binds all handlers and starts listening on the configured port
func StartServer() error {
	r := chi.NewRouter()

	// Base middlewares
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(IPBlockMiddleware)
	if AppConfig.Dev {
		r.Use(LoggerMiddleware(&log.Logger))
	}
	r.Use(middleware.Recoverer)

	// API Routing
	r.Route("/api", func(r chi.Router) {
		r.Get("/auth/google/login", AuthLoginHandler)
		r.Get("/auth/google/callback", AuthCallbackHandler)
		r.Get("/auth/logout", AuthLogoutHandler)
		r.Get("/auth/me", AuthMeHandler)

		r.Get("/config", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(fmt.Sprintf(`{"contact_email": "%s", "max_secret_length": %d, "google_tag_id": "%s", "max_ttl_hours": %d, "hide_footer": %t}`, AppConfig.ContactEmail, AppConfig.MaxSecretLength, AppConfig.GoogleTagID, AppConfig.MaxTTLHours, AppConfig.HideFooter)))
		})

		// Secrets API (Protected creates string, unprotected reads string)
		r.Route("/secrets", func(r chi.Router) {
			r.With(AuthMiddleware).Post("/", CreateSecretHandler)

			r.Route("/{id}", func(r chi.Router) {
				if AppConfig.RateLimitReq > 0 {
					r.Use(httprate.Limit(
						AppConfig.RateLimitReq,
						AppConfig.RateLimitWin,
						httprate.WithKeyByIP(), // Note middleware.RealIP ensure the remote address is correct
						httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
							log.Warn().Str("ip", r.RemoteAddr).Str("path", r.URL.Path).Msg("Rate limit exceeded")
							http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
						}),
					))
				}
				r.Get("/metadata", GetSecretMetadataHandler)
				r.Post("/reveal", RevealSecretHandler)
			})
		})
	})

	// Setup Catch-All Route for Single Page App serving
	FileServer(r, "/", http.FS(frontend.FS))

	bindAddr := fmt.Sprintf(":%d", AppConfig.Port)
	log.Info().Str("bind", bindAddr).Msg("Server starting")

	return http.ListenAndServe(bindAddr, r)
}

// FileServer conveniently sets up a http.FileServer handler to serve
// static files from a http.FileSystem. It additionally handles SPA routing fallback.
func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		log.Fatal().Msg("FileServer does not permit any URL parameters")
	}

	fs := http.StripPrefix(path, http.FileServer(root))

	r.Get(path+"*", func(w http.ResponseWriter, r *http.Request) {
		// If trying to access a file that might exist, serve it via the FileServer. Wait, actually we fallback to index.html if it doesn't.

		f, err := root.Open(strings.TrimPrefix(r.URL.Path, path))
		if err == nil {
			f.Close()
			fs.ServeHTTP(w, r)
			return
		}

		// Serve index.html as fallback for Client-side Routing
		index, err := root.Open("index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		defer index.Close()

		stat, _ := index.Stat()
		http.ServeContent(w, r, "index.html", stat.ModTime(), index)
	})
}

// IPBlockMiddleware globally intercepts requests from disallowed IPs
func IPBlockMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isIPBlocked(r.RemoteAddr) {
			// We return blocked.html directly for web requests, or JSON for API calls
			if strings.HasPrefix(r.URL.Path, "/api") {
				http.Error(w, `{"error":"ip_blocked", "message": "Access blocked due to malicious activity"}`, http.StatusForbidden)
				return
			}

			// For UI / Assets requests: load blocked HTML
			content, err := frontend.FS.ReadFile("blocked.html")
			if err != nil {
				http.Error(w, "Access blocked due to malicious activity.", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			w.Write(content)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isIPBlocked(ip string) bool {
	// Use feature flag store to validate IPs
	if AppConfig.FFBlockedIPs != "" {
		ctx := ffcontext.NewEvaluationContext(ip)
		blocked, err := ffs.Client().BoolVariationDetails(AppConfig.FFBlockedIPs, ctx, false)
		if err != nil {
			log.Error().Err(err).Msg("fflags: failed to get blocked ips")
			return false
		}
		if blocked.Value {
			var reason string
			if val, ok := blocked.Metadata["evaluatedRuleName"]; ok {
				reason = val.(string)
			} else {
				reason = "unknown"
			}
			log.Warn().Str("ip", ip).Str("reason", reason).Msg("fflags: blocked ip")
			return true
		}
		return false
	}

	// Fallback to static list of blocked IPs
	if len(AppConfig.BlockedIPs) > 0 {
		for _, blockedIP := range AppConfig.BlockedIPs {
			if ip == blockedIP || strings.HasPrefix(ip, blockedIP) {
				log.Warn().Str("ip", ip).Msg("blocked ip")
				return true
			}
		}
	}
	return false
}
