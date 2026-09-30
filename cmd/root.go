package cmd

import (
	"cmp"
	"context"
	"fmt"
	"k8xauth/internal/logger"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	Version   string
	Commit    string
	BuildDate string
)

var RootCmd = &cobra.Command{
	Use:   "k8xauth",
	Short: "Kubernetes cluster cross-cloud authenticator",
	Long: `Kubernetes execProviderConfig authenticator for Identity based
authentication of clusters running on different cloud providers or on premise
without the need to use long-term credentials.`,
	CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := RootCmd.ExecuteContext(ctx)
	if err != nil {
		stop()
		os.Exit(1)
	}
}

// buildVersion returns the version, commit and build date, preferring values injected
// via -ldflags and falling back to the VCS info the go command stamps into the binary.
func buildVersion() (version, commit, buildDate string) {
	version, commit, buildDate = Version, Commit, BuildDate
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "(devel)" {
			version = cmp.Or(version, info.Main.Version)
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				commit = cmp.Or(commit, s.Value[:min(len(s.Value), 7)])
			case "vcs.time":
				buildDate = cmp.Or(buildDate, s.Value)
			}
		}
	}
	return cmp.Or(version, "dev"), cmp.Or(commit, "unknown"), cmp.Or(buildDate, "unknown")
}

func versionString() string {
	version, commit, buildDate := buildVersion()
	return fmt.Sprintf(
		"Version:    %s\nCommit:     %s\nBuild date: %s\nGo version: %s\nOS/Arch:    %s/%s\n",
		version, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH,
	)
}

func init() {
	RootCmd.Version, _, _ = buildVersion()
	RootCmd.SetVersionTemplate(versionString())
	RootCmd.PersistentFlags().String("authsource", "all", "Authentication source to use [gke|eks|aks|all] (optional)")
	RootCmd.PersistentFlags().Bool("printsourceauthtoken", false, "Print source authentication token, useful for debugging. May expose sensitive data")
	RootCmd.PersistentFlags().String("loglevel", "info", "Set log level [debug|info|warn|error] (optional)")
	RootCmd.PersistentFlags().String("logformat", "text", "Set log format [text|json] (optional)")
	RootCmd.PersistentFlags().String("logfile", "", "Set log file. If not set logs are sent to standard output (optional)")
}
