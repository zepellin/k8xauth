package genericoidc

import (
	"k8xauth/cmd"
	"k8xauth/internal/auth"

	"github.com/spf13/cobra"
)

var genericOIDCCmd = &cobra.Command{
	Use:   "generic-oidc",
	Short: "Fetches generic OIDC exec credentials",
	Long: `Fetches generic OIDC exec credentials from GKE, EKS, or AKS workload identities.

This is useful for cases where a Kubernetes client only needs the source OIDC token
without any cloud-provider specific token exchange or transformation.`,
	Example: `k8xauth generic-oidc --authsource gke --audience "my-audience"
k8xauth generic-oidc --authsource eks
k8xauth generic-oidc --authsource aks --audience "api://custom-app/.default"`,
	Run: func(cmd *cobra.Command, args []string) {
		audience, _ := cmd.Flags().GetString("audience")

		options := auth.Options{
			AuthType:         cmd.Flag("authsource").Value.String(),
			Audience:         audience,
			PrintSourceToken: cmd.Flag("printsourceauthtoken").Value.String() == "true",
		}

		getCredentials(&options)
	},
}

func init() {
	cmd.RootCmd.AddCommand(genericOIDCCmd)

	genericOIDCCmd.Flags().String("audience", "", "Audience or scope to request for the source OIDC token (optional)")
}
