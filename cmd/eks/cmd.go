package eks

import (
	"k8xauth/cmd"
	auth "k8xauth/internal/auth"

	"github.com/spf13/cobra"
)

// eksCmd represents the eks command
var eksCmd = &cobra.Command{
	Use:   "eks",
	Short: "Fetches AWS EKS cluster credentials",
	Long: `Fetches AWS EKS cluster credentials from GKE or AKS Workload Identity

This is useful for cases where  Kubernetes client is running in GKE or AKS cluster
and needs to manage external AWS EKS cluster(s)`,
	Example: `k8xauth eks --rolearn "arn:aws:iam::123456789012:role/argocd-platform" --stsregion "us-east-2" --cluster "my-cluster-name"`,
	Run: func(cmd *cobra.Command, args []string) {

		rolearn, _ := cmd.Flags().GetString("rolearn")
		cluster, _ := cmd.Flags().GetString("cluster")
		stsregion, _ := cmd.Flags().GetString("stsregion")

		options := auth.Options{
			AuthType:         cmd.Flag("authsource").Value.String(),
			PrintSourceToken: cmd.Flag("printsourceauthtoken").Value.String() == "true",
		}

		getCredentials(&options, rolearn, cluster, stsregion)
	},
}

func init() {
	cmd.RootCmd.AddCommand(eksCmd)

	eksCmd.Flags().StringP("rolearn", "r", "", "AWS role ARN to assume (required)")
	eksCmd.Flags().StringP("cluster", "c", "", "AWS EKS cluster name for which we fetch credentials (required)")
	eksCmd.Flags().StringP("stsregion", "s", "us-east-1", "AWS STS region to which requests are made (optional)")
	eksCmd.MarkFlagRequired("rolearn")
	eksCmd.MarkFlagRequired("cluster")
}
