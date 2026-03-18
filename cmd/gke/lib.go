package gke

import (
	"k8xauth/internal/logger"

	"context"
	"fmt"
	"io"
	auth "k8xauth/internal/auth"
	"k8xauth/internal/credwriter"
	"os"
	"time"

	"google.golang.org/api/iamcredentials/v1"

	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/api/sts/v1"
)

const (
	GRANT_TYPE           = "urn:ietf:params:oauth:grant-type:token-exchange"
	REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
	SUBJECT_TOKEN_TYPE   = "urn:ietf:params:oauth:token-type:jwt"
	SCOPE                = "https://www.googleapis.com/auth/cloud-platform"
)

type tokenProvider interface {
	Token() (*oauth2.Token, error)
	PrettyPrintJWTToken(w io.Writer) error
}

type execCredentialWriter interface {
	Write(token oauth2.Token, writer ...io.Writer) error
}

type stsExchangeResult struct {
	AccessToken string
	ExpiresIn   int64
}

func defaultTokenProviderFactory(o *auth.Options) (tokenProvider, error) {
	return auth.New(o)
}

func defaultSTSExchange(ctx context.Context, identityToken oauth2.Token, idProvider string) (stsExchangeResult, error) {
	stsExchangeTokenRequest := sts.GoogleIdentityStsV1ExchangeTokenRequest{
		GrantType:          GRANT_TYPE,
		RequestedTokenType: REQUESTED_TOKEN_TYPE,
		SubjectTokenType:   SUBJECT_TOKEN_TYPE,
		Audience:           idProvider,
		Scope:              SCOPE,
		SubjectToken:       identityToken.AccessToken,
	}

	gcpStsService, err := sts.NewService(ctx, option.WithoutAuthentication())
	if err != nil {
		return stsExchangeResult{}, err
	}

	gcpStsV1Service := sts.NewV1Service(gcpStsService)
	stsToken, err := gcpStsV1Service.Token(&stsExchangeTokenRequest).Do()
	if err != nil {
		return stsExchangeResult{}, err
	}

	return stsExchangeResult{AccessToken: stsToken.AccessToken, ExpiresIn: stsToken.ExpiresIn}, nil
}

func defaultServiceAccountTokenExchange(ctx context.Context, stsOAuthToken oauth2.Token, gcpServiceAccount string) (oauth2.Token, error) {
	config := &oauth2.Config{}
	iamCredentialsService, err := iamcredentials.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, &stsOAuthToken)))
	if err != nil {
		return oauth2.Token{}, err
	}

	accessTokenRequest := iamcredentials.GenerateAccessTokenRequest{
		Lifetime: "3600s",
		Scope:    []string{SCOPE},
	}

	gcpCredentials, err := iamCredentialsService.Projects.ServiceAccounts.GenerateAccessToken("projects/-/serviceAccounts/"+gcpServiceAccount, &accessTokenRequest).Do()
	if err != nil {
		return oauth2.Token{}, err
	}

	return oauth2.Token{AccessToken: gcpCredentials.AccessToken}, nil
}

func getCredentials(o *auth.Options, projectId, poolId, providerId, gcpServiceAccount string) {
	idProvider := fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectId, poolId, providerId)
	err := writeCredentials(o, idProvider, gcpServiceAccount, os.Stdout, defaultTokenProviderFactory, defaultSTSExchange, defaultServiceAccountTokenExchange, &credwriter.ExecCredentialWriter{}, time.Now)
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
}

func writeCredentials(
	o *auth.Options,
	idProvider, gcpServiceAccount string,
	output io.Writer,
	authFactory func(*auth.Options) (tokenProvider, error),
	stsExchange func(context.Context, oauth2.Token, string) (stsExchangeResult, error),
	serviceAccountExchange func(context.Context, oauth2.Token, string) (oauth2.Token, error),
	writer execCredentialWriter,
	now func() time.Time,
) error {
	authSource, err := authFactory(o)
	if err != nil {
		return fmt.Errorf("failed to initialize source authentication: %w", err)
	}

	if o.PrintSourceToken {
		if err := authSource.PrettyPrintJWTToken(output); err != nil {
			return fmt.Errorf("failed to print source token: %w", err)
		}
	}

	identityToken, err := authSource.Token()
	if err != nil {
		return fmt.Errorf("failed to retrieve source token: %w", err)
	}

	stsToken, err := stsExchange(context.Background(), *identityToken, idProvider)
	if err != nil {
		return fmt.Errorf("failed to exchange source token with GCP STS: %w", err)
	}

	if gcpServiceAccount == "" {
		if err := writer.Write(oauth2.Token{
			AccessToken: stsToken.AccessToken,
			Expiry:      now().Add(time.Second * time.Duration(stsToken.ExpiresIn)),
		}, output); err != nil {
			return fmt.Errorf("failed to write exec credential: %w", err)
		}
		return nil
	}

	stsOauthToken := oauth2.Token{
		AccessToken: stsToken.AccessToken,
		Expiry:      now().Add(time.Second * time.Duration(stsToken.ExpiresIn)),
	}

	gcpCredentials, err := serviceAccountExchange(context.Background(), stsOauthToken, gcpServiceAccount)
	if err != nil {
		return fmt.Errorf("failed to exchange STS token for GCP service account credentials: %w", err)
	}

	if err := writer.Write(oauth2.Token{
		AccessToken: gcpCredentials.AccessToken,
		Expiry:      now().Add(time.Second * time.Duration(stsToken.ExpiresIn)),
	}, output); err != nil {
		return fmt.Errorf("failed to write exec credential: %w", err)
	}

	return nil
}
