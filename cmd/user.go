package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"github.com/skymeyer/onetime-secret/backend"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var userCmd = &cobra.Command{
	Use:   "lookup-user [id]",
	Short: "Lookup user from user store",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			ctx        = cmd.Context()
			userBucket = viper.GetString("user-bucket")
			userID     = args[0]
		)
		if userBucket == "" {
			return fmt.Errorf("user-bucket not set")
		}

		client, err := storage.NewClient(ctx)
		if err != nil {
			return err
		}
		defer client.Close()

		obj, err := client.Bucket(userBucket).Object(userID).NewReader(ctx)
		if err != nil {
			return err
		}
		defer obj.Close()

		data, err := io.ReadAll(obj)
		if err != nil {
			return err
		}

		var user backend.UserInfo
		if err := json.Unmarshal(data, &user); err != nil {
			return err
		}

		pretty, _ := json.MarshalIndent(user, "", "    ")
		fmt.Println(string(pretty))
		return nil
	},
}
