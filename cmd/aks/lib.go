package aks

import (
	auth "k8xauth/internal/auth"
	"k8xauth/internal/credwriter"
	"k8xauth/internal/logger"

	"context"
	"fmt"
	"io"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	statictokensource "github.com/trhyo/azidentity-static-source"
	"golang.org/x/oauth2"
)

type tokenProvider interface {
	Token() (*oauth2.Token, error)
	PrettyPrintJWTToken(w io.Writer) error
}

type execCredentialWriter interface {
	Write(token oauth2.Token, writer ...io.Writer) error
}

func defaultTokenProviderFactory(o *auth.Options) (tokenProvider, error) {
	return auth.New(o)
}

func defaultAzureTokenExchange(ctx context.Context, identityToken *oauth2.Token, clientID, tenantID, serverID string) (oauth2.Token, error) {
	logger.Log.Debug("Getting Azure client credentials")
	defaultAzureCredentialOptions := azidentity.DefaultAzureCredentialOptions{
		TenantID: tenantID,
	}

	defaultCredentials, err := azidentity.NewDefaultAzureCredential(&defaultAzureCredentialOptions)
	if err != nil {
		logger.Log.Debug(fmt.Sprintf("Error getting default Azure credentials: %s", err.Error()))
	}

	workloadIdentityFederationCredentialOptions := statictokensource.WorkloadIdentityFederationCredentialOptions{
		DisableInstanceDiscovery: true,
		TenantID:                 tenantID,
		ClientID:                 clientID,
		FederatedToken:           *identityToken,
	}

	wfiCredentials, err := statictokensource.NewWorkloadIdentityFederationCredential(&workloadIdentityFederationCredentialOptions)
	if err != nil {
		return oauth2.Token{}, err
	}

	chainCreds, err := azidentity.NewChainedTokenCredential([]azcore.TokenCredential{wfiCredentials, defaultCredentials}, nil)
	if err != nil {
		return oauth2.Token{}, err
	}

	aztoken, err := chainCreds.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{serverID + "/.default"},
	})
	if err != nil {
		return oauth2.Token{}, err
	}

	return oauth2.Token{
		AccessToken: aztoken.Token,
		Expiry:      aztoken.ExpiresOn,
	}, nil
}

func getCredentials(o *auth.Options, clientID, tenantID, serverID string) {
	err := writeCredentials(o, clientID, tenantID, serverID, os.Stdout, defaultTokenProviderFactory, defaultAzureTokenExchange, &credwriter.ExecCredentialWriter{})
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
}

func writeCredentials(
	o *auth.Options,
	clientID, tenantID, serverID string,
	output io.Writer,
	authFactory func(*auth.Options) (tokenProvider, error),
	tokenExchange func(context.Context, *oauth2.Token, string, string, string) (oauth2.Token, error),
	writer execCredentialWriter,
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

	azToken, err := tokenExchange(context.Background(), identityToken, clientID, tenantID, serverID)
	if err != nil {
		return fmt.Errorf("failed to exchange source token for Azure credentials: %w", err)
	}

	if err := writer.Write(azToken, output); err != nil {
		return fmt.Errorf("failed to write exec credential: %w", err)
	}

	return nil
}
