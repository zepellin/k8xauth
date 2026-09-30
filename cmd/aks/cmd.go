package aks

import (
	"k8xauth/cmd"
	"k8xauth/internal/auth"

	"github.com/spf13/cobra"
)

const (
	DEFAULT_AAD_SERVER_APPLICATION_ID = "6dae42f8-4368-4678-94ff-3960e28e3630"
)

// aksCmd represents the aks command
var aksCmd = &cobra.Command{
	Use:   "aks",
	Short: "Fetches Azure AKS cluster credentials",
	Long: `Fetches Azure AKS cluster credentials from GKE Workload Identity, EKS IRSA
or a Kubernetes service account token

This is useful for cases where Kubernetes client is running in GKE, EKS or any other Kubernetes cluster
and needs to manage external Azure AKS cluster(s)`,
	Example: `k8xauth aks --tenantid "12345678-1234-1234-1234-123456789abc" --clientid "12345678-1234-1234-1234-123456789abc"`,
	Run: func(cmd *cobra.Command, args []string) {

		tenantID, _ := cmd.Flags().GetString("tenantid")
		clientID, _ := cmd.Flags().GetString("clientid")
		serverID, _ := cmd.Flags().GetString("serverid")

		options := auth.Options{
			AuthType:         cmd.Flag("authsource").Value.String(),
			TokenFile:        cmd.Flag("sourcetokenfile").Value.String(),
			PrintSourceToken: cmd.Flag("printsourceauthtoken").Value.String() == "true",
		}

		getCredentials(cmd.Context(), &options, clientID, tenantID, serverID)
	},
}

func init() {
	cmd.RootCmd.AddCommand(aksCmd)

	aksCmd.Flags().StringP("tenantid", "t", "", "Azure Entra Directory tenant ID (required)")
	aksCmd.Flags().StringP("clientid", "c", "", "Azure Managed Principal/App client ID (required)")
	aksCmd.Flags().StringP("serverid", "s", DEFAULT_AAD_SERVER_APPLICATION_ID, "Azure Entra (AAD) server app ID (optional)") // https://azure.github.io/kubelogin/concepts/aks.html
	aksCmd.MarkFlagRequired("tenantid")
	aksCmd.MarkFlagRequired("clientid")
}
