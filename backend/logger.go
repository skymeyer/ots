package backend

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// InitLogger initializes the global slog instance with GCP-friendly configurations.
func InitLogger(levelStr string, dev bool) {
	// Parse configured log level securely
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var handler slog.Handler
	if dev {
		// Local console-friendly format
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey {
					a.Value = slog.StringValue(a.Value.Time().Format("15:04:05"))
				}
				return a
			},
		})
	} else {
		// GCP Cloud Run JSON-friendly format
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.LevelKey {
					a.Key = "severity"
					lvl := a.Value.Any().(slog.Level)
					switch lvl {
					case slog.LevelDebug:
						a.Value = slog.StringValue("DEBUG")
					case slog.LevelInfo:
						a.Value = slog.StringValue("INFO")
					case slog.LevelWarn:
						a.Value = slog.StringValue("WARNING")
					case slog.LevelError:
						a.Value = slog.StringValue("ERROR")
					default:
						a.Value = slog.StringValue(lvl.String())
					}
				} else if a.Key == slog.TimeKey {
					a.Key = "timestamp"
				}
				return a
			},
		})
	}

	slog.SetDefault(slog.New(handler))
}

// LoggerMiddleware is a custom chi-middleware that bridges chi requests to slog
func LoggerMiddleware(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wraps the response writer to capture statusCode
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				// We log requests globally after completion
				// Calculating duration
				latency := time.Since(start)

				// Log using GCP friendly format
				var level slog.Level = slog.LevelInfo
				if ww.Status() >= 500 {
					level = slog.LevelError
				} else if ww.Status() >= 400 {
					level = slog.LevelWarn
				}

				logger.Log(r.Context(), level, "HTTP Request",
					"method", r.Method,
					"path", r.URL.Path,
					"remote_ip", r.RemoteAddr,
					"user_agent", r.UserAgent(),
					"status", ww.Status(),
					"latency", latency,
				)
			}()

			// Call next handler
			next.ServeHTTP(ww, r)
		})
	}
}
