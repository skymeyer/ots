package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/skymeyer/onetime-secret/backend"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start server",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize Config directly from Viper
		backend.AppConfig = backend.Config{
			Dev:              viper.GetBool("dev"),
			LogLevel:         viper.GetString("log-level"),
			GoogleClientID:   viper.GetString("google-client-id"),
			GoogleSecret:     viper.GetString("google-client-secret"),
			GoogleScopes:     backend.ParseList(viper.GetString("google-scopes")),
			AllowedEmails:    backend.ParseList(viper.GetString("allowed-emails")),
			AllowedDomains:   backend.ParseList(viper.GetString("allowed-domains")),
			BlockedEmails:    backend.ParseList(viper.GetString("blocked-emails")),
			BlockedIPs:       backend.ParseList(viper.GetString("blocked-ips")),
			MaxSecretLength:  viper.GetInt("max-secret-length"),
			DefaultTTLHours:  viper.GetInt("default-ttl"),
			MaxTTLHours:      viper.GetInt("max-ttl"),
			ContactEmail:     viper.GetString("contact-email"),
			GoogleTagID:      viper.GetString("google-tag-id"),
			HideFooter:       viper.GetBool("hide-footer"),
			Port:             viper.GetInt("port"),
			RateLimitReq:     viper.GetInt("rate-limit-requests"),
			RateLimitWin:     viper.GetDuration("rate-limit-window"),
			PublicURL:        viper.GetString("public-url"),
			ProjectID:        viper.GetString("project-id"),
			KMSLocation:      viper.GetString("kms-location"),
			KMSKeyRing:       viper.GetString("kms-key-ring"),
			KMSKey:           viper.GetString("kms-key"),
			DEKSecret:        viper.GetString("dek-secret"),
			SecretBucket:     viper.GetString("secret-bucket"),
			UserBucket:       viper.GetString("user-bucket"),
			FFFile:           viper.GetString("ff-file"),
			FFAuthzDomains:   viper.GetString("ff-authz-domains"),
			FFAuthzEmails:    viper.GetString("ff-authz-emails"),
			FFBlockEmails:    viper.GetString("ff-block-emails"),
			FFBlockedIPs:     viper.GetString("ff-blocked-ips"),
			FFRefreshSeconds: viper.GetInt("ff-refresh-seconds"),
			SessionSecret:    viper.GetString("session-secret"),
		}

		backend.InitLogger(backend.AppConfig.LogLevel, backend.AppConfig.Dev)
		slog.Info("Logger initialized successfully", "version", getVersion().String())

		// Security: Fallback to a random session secret if none provided in dev
		if backend.AppConfig.SessionSecret == "" {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				slog.Error("Failed to generate session secret", "error", err)
				os.Exit(1)
			}
			backend.AppConfig.SessionSecret = hex.EncodeToString(b)
			slog.Warn("No session secret provided, generated a random one")
		}

		// Initialize secret store
		var (
			ctx = cmd.Context()
			kek = fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
				backend.AppConfig.ProjectID,
				backend.AppConfig.KMSLocation,
				backend.AppConfig.KMSKeyRing,
				backend.AppConfig.KMSKey,
			)
			dek = fmt.Sprintf("projects/%s/secrets/%s",
				backend.AppConfig.ProjectID,
				backend.AppConfig.DEKSecret,
			)
		)
		if err := backend.InitSecretStore(ctx, kek, dek,
			backend.AppConfig.SecretBucket, backend.AppConfig.UserBucket); err != nil {
			return err
		}
		slog.Info("Secret store initialized", "secret-bucket", backend.AppConfig.SecretBucket, "kek", kek, "dek", dek)

		// Initialize feature flags if enabled
		if backend.AppConfig.FFFile != "" && backend.AppConfig.FFAuthzDomains != "" && backend.AppConfig.FFAuthzEmails != "" && backend.AppConfig.FFBlockEmails != "" {
			refresh := time.Duration(backend.AppConfig.FFRefreshSeconds) * time.Second
			if err := backend.InitFFManager(backend.AppConfig.FFFile, refresh); err != nil {
				return err
			}
			slog.Info("Feature flags initialized", "refresh", refresh, "file", backend.AppConfig.FFFile)
		}

		// Start Server
		return backend.StartServer()
	},
}
