package gke

import (
	"k8xauth/internal/logger"

	"context"
	"fmt"
	"io"
	auth "k8xauth/internal/auth"
	"k8xauth/internal/credwriter"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
)

const (
	SUBJECT_TOKEN_TYPE         = "urn:ietf:params:oauth:token-type:jwt"
	SCOPE                      = "https://www.googleapis.com/auth/cloud-platform"
	IMPERSONATION_URL_TEMPLATE = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
	AUDIENCE_TEMPLATE          = "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s"
)

type tokenProvider interface {
	Token() (*oauth2.Token, error)
	PrettyPrintJWTToken(w io.Writer) error
}

type execCredentialWriter interface {
	Write(token oauth2.Token, writer ...io.Writer) error
}

// sourceTokenSupplier feeds the source identity token into the GCP STS token exchange.
type sourceTokenSupplier struct {
	source tokenProvider
}

func (s sourceTokenSupplier) SubjectToken(_ context.Context, _ externalaccount.SupplierOptions) (string, error) {
	token, err := s.source.Token()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve source token: %w", err)
	}
	return token.AccessToken, nil
}

func defaultTokenProviderFactory(ctx context.Context, o *auth.Options) (tokenProvider, error) {
	return auth.New(ctx, o)
}

// newExternalAccountConfig builds the GCP Workload Identity Federation config. When gcpServiceAccount is set,
// the STS token is additionally exchanged for an access token of that service account.
func newExternalAccountConfig(projectId, poolId, providerId, gcpServiceAccount string) externalaccount.Config {
	conf := externalaccount.Config{
		Audience:         fmt.Sprintf(AUDIENCE_TEMPLATE, projectId, poolId, providerId),
		SubjectTokenType: SUBJECT_TOKEN_TYPE,
		Scopes:           []string{SCOPE},
	}
	if gcpServiceAccount != "" {
		conf.ServiceAccountImpersonationURL = fmt.Sprintf(IMPERSONATION_URL_TEMPLATE, gcpServiceAccount)
	}
	return conf
}

func getCredentials(ctx context.Context, o *auth.Options, projectId, poolId, providerId, gcpServiceAccount string) {
	conf := newExternalAccountConfig(projectId, poolId, providerId, gcpServiceAccount)
	err := writeCredentials(ctx, o, conf, os.Stdout, defaultTokenProviderFactory, &credwriter.ExecCredentialWriter{})
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
}

func writeCredentials(
	ctx context.Context,
	o *auth.Options,
	conf externalaccount.Config,
	output io.Writer,
	authFactory func(context.Context, *auth.Options) (tokenProvider, error),
	writer execCredentialWriter,
) error {
	authSource, err := authFactory(ctx, o)
	if err != nil {
		return fmt.Errorf("failed to initialize source authentication: %w", err)
	}

	if o.PrintSourceToken {
		if err := authSource.PrettyPrintJWTToken(output); err != nil {
			if logger.Log != nil {
				logger.Log.Warn("Failed to print source token", "error", err.Error())
			}
		}
	}

	conf.SubjectTokenSupplier = sourceTokenSupplier{source: authSource}
	ts, err := externalaccount.NewTokenSource(ctx, conf)
	if err != nil {
		return fmt.Errorf("failed to configure GCP workload identity federation: %w", err)
	}

	gcpToken, err := ts.Token()
	if err != nil {
		return fmt.Errorf("failed to exchange source token for GCP access token: %w", err)
	}

	if err := writer.Write(*gcpToken, output); err != nil {
		return fmt.Errorf("failed to write exec credential: %w", err)
	}

	return nil
}
