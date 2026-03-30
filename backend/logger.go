package backend

import (
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger initializes the global zerolog instance with GCP-friendly configurations.
func InitLogger(levelStr string, dev bool) {
	// GCP expects the severity field instead of level
	zerolog.LevelFieldName = "severity"
	// GCP expects timestamp field to be timestamp
	zerolog.TimestampFieldName = "timestamp"

	// Parse configured log level securely
	level, err := zerolog.ParseLevel(levelStr)
	if err != nil {
		level = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(level)

	// In a real GCP environment without a TTY, outputting to os.Stdout directly in JSON format is preferred.
	// Since chi operates on a request basis, we'll setup the global logger.
	var writer io.Writer
	if dev {
		writer = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}
	} else {
		writer = os.Stdout
	}
	log.Logger = zerolog.New(writer).With().Timestamp().Logger()

	log.Info().Str("level", level.String()).Msg("Logger initialized successfully")
}

// LoggerMiddleware is a custom chi-middleware that bridges chi requests to zerolog
func LoggerMiddleware(logger *zerolog.Logger) func(next http.Handler) http.Handler {
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
				event := logger.Info()
				if ww.Status() >= 500 {
					event = logger.Error()
				} else if ww.Status() >= 400 {
					event = logger.Warn()
				}

				event.
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Str("remote_ip", r.RemoteAddr).
					Str("user_agent", r.UserAgent()).
					Int("status", ww.Status()).
					Dur("latency", latency).
					Msg("HTTP Request")
			}()

			// Call next handler
			next.ServeHTTP(ww, r)
		})
	}
}
