package backend

import (
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/thomaspoignant/go-feature-flag/ffcontext"
)

// Config holds all the application configuration settings
type Config struct {
	Dev             bool
	LogLevel        string
	GoogleClientID  string
	GoogleSecret    string
	GoogleScopes    []string
	AllowedEmails   []string
	AllowedDomains  []string
	BlockedEmails   []string
	BlockedIPs      []string
	MaxSecretLength int
	DefaultTTLHours int
	MaxTTLHours     int
	ContactEmail    string
	GoogleTagID     string // Google Analytics Tag ID
	HideFooter      bool   // Hide the global website footer
	Port            int
	RateLimitReq    int
	RateLimitWin    time.Duration
	SessionSecret   string // Used for signing cookies
	PublicURL       string // e.g. http://localhost:8080 or https://example.com

	ProjectID    string // GCP Project ID
	KMSLocation  string // KMS Location
	KMSKeyRing   string // GCP KMS Key Ring
	KMSKey       string // GCP KMS Key
	DEKSecret    string // GCP Secret Name for DEK
	SecretBucket string // GCS Bucket Name
	UserBucket   string // Optional GCS bucket to store user information

	FFFile           string // GCS File for feature flags
	FFAuthzDomains   string // Feature flag name to authorize domains
	FFAuthzEmails    string // Feature flag name to authorize emails
	FFBlockEmails    string // Feature flag name to block emails
	FFBlockedIPs     string // Feature flag name to block IPs
	FFRefreshSeconds int    // Feature flags refresh interval
}

// Global variable assuming app operates purely on a single global config
var AppConfig Config

// ParseList is a helper to clean up comma separated configs
func ParseList(in string) []string {
	var out []string
	parts := strings.Split(in, ",")
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (c *Config) IsAllowed(ui *UserInfo) bool {

	if ffs != nil {
		return c.FeatureFlagAuthz(ui)
	}

	// Check allowed domains
	for _, ad := range c.AllowedDomains {
		if strings.EqualFold(ad, ui.Domain()) {
			log.Debug().Str("user", ui.ID).Str("domain", ui.Domain()).Msg("user allowed via domain")
			return true
		}
	}

	// Check allowed emails
	for _, ae := range c.AllowedEmails {
		if strings.EqualFold(ae, ui.Email) {
			log.Debug().Str("user", ui.ID).Msg("user allowed via email")
			return true
		}
	}

	// If both slices are empty, effectively everyone is blocked.
	log.Warn().Str("user", ui.ID).Msg("unauthorized login attempt")
	return false
}

func (c *Config) FeatureFlagAuthz(ui *UserInfo) bool {

	var (
		allowed bool
		err     error
	)

	ctx := ffcontext.NewEvaluationContext(ui.ID)
	ctx.AddCustomAttribute("email", ui.Email)
	ctx.AddCustomAttribute("domain", ui.Domain())

	// Check if user is blocked
	blocked, err := ffs.Client().BoolVariation(c.FFBlockEmails, ctx, false)
	if err != nil {
		log.Error().Err(err).Msg("fflags: failed to get blocked users")
	}
	if blocked {
		log.Warn().Str("user", ui.ID).Msg("fflags: blocked user login attempt")
		return false
	}

	// Authorize domains
	allowed, err = ffs.Client().BoolVariation(c.FFAuthzDomains, ctx, false)
	if err != nil {
		log.Error().Err(err).Msg("fflags: failed to get allowed domains")
	}
	if allowed {
		log.Debug().Str("user", ui.ID).Str("domain", ui.Domain()).Msg("fflags: user allowed via domain")
		return true
	}

	// Authorize individual users
	allowed, err = ffs.Client().BoolVariation(c.FFAuthzEmails, ctx, false)
	if err != nil {
		log.Error().Err(err).Msg("fflags: failed to get allowed users")
	}
	if allowed {
		log.Debug().Str("user", ui.ID).Msg("fflags: user allowed via email")
		return true
	}

	log.Warn().Str("user", ui.ID).Msg("fflags: unauthorized login attempt")
	return false
}

func (c *Config) IsSecureCookie() bool {
	return strings.HasPrefix(c.PublicURL, "https")
}
