package cmd

import (
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "ots",
	Short: "A one-time secret sharing web application",
	Long:  `A lightweight, zero-dependency frontend web application served by a Go backend, allowing users to securely share secrets via one-time unique URLs.`,
}

func Execute() error {
	rootCmd.AddCommand(serverCmd, dekCmd, userCmd)
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.onetime-secret.yaml)")

	serverCmd.Flags().Bool("dev", false, "Enable dev mode, human friendly logging")
	serverCmd.Flags().String("log-level", "info", "Log level (debug, info, warn, error, fatal)")
	serverCmd.Flags().String("google-client-id", "", "Google OAuth2 Client ID")
	serverCmd.Flags().String("google-client-secret", "", "Google OAuth2 Client Secret")
	serverCmd.Flags().String("google-scopes", "openid,email", "Comma separated list of Google OAuth2 scopes (openid and email required)")
	serverCmd.Flags().String("allowed-emails", "", "Comma separated list of explicitly allowed emails")
	serverCmd.Flags().String("allowed-domains", "", "Comma separated list of allowed email domains")
	serverCmd.Flags().String("blocked-emails", "", "Comma separated list of explicitly blocked emails")
	serverCmd.Flags().String("blocked-ips", "", "Comma separated list of IPs to globally block from accessing the service")
	serverCmd.Flags().Int("max-secret-length", 1024, "Maximum length of submitted secrets")
	serverCmd.Flags().Int("default-ttl", 24, "Default time to live in hours for a secret")
	serverCmd.Flags().Int("max-ttl", 168, "Maximum time to live in hours for a secret")
	serverCmd.Flags().String("contact-email", "", "Contact email address shown to unauthorized users")
	serverCmd.Flags().String("google-tag-id", "", "Google Analytics Tag ID (e.g. G-XXXXXXXXXX)")
	serverCmd.Flags().Bool("hide-footer", false, "Hide the website footer from rendering")
	serverCmd.Flags().Int("port", 8080, "Port to listen on")
	serverCmd.Flags().Int("rate-limit-requests", 10, "Number of allowed requests per IP per window on unprotected endpoints")
	serverCmd.Flags().Duration("rate-limit-window", 1*time.Minute, "Duration window for rate limiting unprotected endpoints")
	serverCmd.Flags().String("public-url", "http://localhost:8080", "Public facing URL of the service, used for OAuth callbacks and links")
	serverCmd.Flags().String("session-secret", "", "Secret key used to encrypt the session cookie. Generated randomly if omitted (fine for dev/1-instance)")
	serverCmd.Flags().String("project-id", "", "GCP Project ID")
	serverCmd.Flags().String("kms-location", "", "GCP KMS Location")
	serverCmd.Flags().String("kms-key-ring", "", "GCP KMS Key Ring")
	serverCmd.Flags().String("kms-key", "", "GCP KMS Key")
	serverCmd.Flags().String("dek-secret", "", "GCP Secret Name")
	serverCmd.Flags().String("secret-bucket", "", "GCS Bucket Name for secret storage")
	serverCmd.Flags().String("user-bucket", "", "GCS Bucket Name for users data storage	(optional)")
	serverCmd.Flags().String("ff-file", "", "GCS File for feature flags")
	serverCmd.Flags().String("ff-authz-domains", "", "Feature flag name to authorize domains")
	serverCmd.Flags().String("ff-authz-emails", "", "Feature flag name to authorize emails")
	serverCmd.Flags().String("ff-block-emails", "", "Feature flag name to block emails")
	serverCmd.Flags().String("ff-blocked-ips", "", "Feature flag name to block IPs")
	serverCmd.Flags().Int("ff-refresh-seconds", 300, "Feature flags refresh interval in seconds")

	dekCmd.Flags().String("project-id", "", "GCP Project ID")
	dekCmd.Flags().String("dek-secret", "", "GCP Secret Name")

	userCmd.Flags().String("user-bucket", "", "GCS Bucket Name")

	viper.BindPFlags(serverCmd.Flags())
	viper.BindPFlags(dekCmd.Flags())
	viper.BindPFlags(userCmd.Flags())
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME")
		viper.SetConfigName(".onetime-secret")
	}

	viper.SetEnvPrefix("OTS")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		log.Info().Str("config", viper.ConfigFileUsed()).Msg("Using config file")
	}
}
