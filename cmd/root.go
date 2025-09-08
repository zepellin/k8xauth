package cmd

import (
	"k8xauth/internal/logger"

	"os"

	"github.com/spf13/cobra"
)

var (
	version string
)

var RootCmd = &cobra.Command{
	Use:   "k8xauth",
	Short: "Kubernetes cluster cross-cloud authenticator",
	Long: `Kubernetes execProviderConfig authenticator for Identity based
authentication of clusters running on different cloud providers or on premise
without the need to use long-term credentials.`,
	CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
	Version:           version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logLevel, _ := cmd.Flags().GetString("loglevel")
		logFormat, _ := cmd.Flags().GetString("logformat")
		logFile, _ := cmd.Flags().GetString("logfile")

		logger.New(logLevel, logFormat, logFile)
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().String("authsource", "all", "Authentication source to use [gke|eks|aks|all] (optional)")
	RootCmd.PersistentFlags().Bool("printsourceauthtoken", false, "Print source authentication token, useful for debugging. May expose sensitive data")
	RootCmd.PersistentFlags().String("loglevel", "info", "Set log level [debug|info|warn|error] (optional)")
	RootCmd.PersistentFlags().String("logformat", "text", "Set log format [text|json] (optional)")
	RootCmd.PersistentFlags().String("logfile", "", "Set log file. If not set logs are sent to standard output (optional)")
}
