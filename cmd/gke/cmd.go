package gke

import (
	"k8xauth/cmd"
	"k8xauth/internal/auth"

	"github.com/spf13/cobra"
)

// gkeCmd represents the gke command
var gkeCmd = &cobra.Command{
	Use:   "gke",
	Short: "Fetches Google Cloud GKE cluster credentials",
	Long: `Fetches Google Cloud GKE cluster credentials from AKS Workload Identity or EKS IRSA

This is useful for cases where  Kubernetes client is running in AKS or EKS cluster
and needs to manage external Google Cloud GKE cluster(s)`,
	Example: `k8xauth gke --projectid "12345678901" --poolid "gcp-fed-pool-id" --providerid "gcp-fed-provider-id" --serviceaccount "gcp-sa-name@gcp-project-name.iam.gserviceaccount.com"`,
	Run: func(cmd *cobra.Command, args []string) {

		projectId, _ := cmd.Flags().GetString("projectid")
		poolId, _ := cmd.Flags().GetString("poolid")
		providerId, _ := cmd.Flags().GetString("providerid")
		gcpServiceAccount, _ := cmd.Flags().GetString("serviceaccount")

		options := auth.Options{
			AuthType:         cmd.Flag("authsource").Value.String(),
			PrintSourceToken: cmd.Flag("printsourceauthtoken").Value.String() == "true",
		}

		getCredentials(cmd.Context(), &options, projectId, poolId, providerId, gcpServiceAccount)
	},
}

func init() {
	cmd.RootCmd.AddCommand(gkeCmd)

	gkeCmd.Flags().String("poolid", "", "GCP Worload Identity Federation pool ID (required)")
	gkeCmd.Flags().String("providerid", "", "GCP Worload Identity Federation provider ID (required)")
	gkeCmd.Flags().StringP("projectid", "p", "", "Numerical GCP project ID (required)")
	gkeCmd.Flags().StringP("serviceaccount", "s", "", "GCP Service Account to generate access token for (optional)")
	gkeCmd.MarkFlagRequired("projectid")
	gkeCmd.MarkFlagRequired("poolid")
	gkeCmd.MarkFlagRequired("providerid")
}
