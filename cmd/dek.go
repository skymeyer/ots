package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"go.skymeyer.dev/pkg/crypto"
)

var dekCmd = &cobra.Command{
	Use:   "rotate-dek",
	Short: "Rotate or initialize DEK secret",
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			ctx       = cmd.Context()
			projectID = viper.GetString("project-id")
			dekSecret = viper.GetString("dek-secret")
		)
		if projectID == "" || dekSecret == "" {
			return fmt.Errorf("project-id and dek-secret are required")
		}
		sm, err := crypto.NewSecretManager(ctx, projectID)
		if err != nil {
			return err
		}
		defer sm.Close()
		version, err := sm.RotateDEK(ctx, dekSecret)
		if err != nil {
			return err
		}
		fmt.Printf("New DEK secret version: %s\n", version)
		return nil
	},
}
