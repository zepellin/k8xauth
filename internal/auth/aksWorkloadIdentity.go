package auth

import (
	"k8xauth/internal/logger"
	"time"

	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"golang.org/x/oauth2"
)

const (
	defaultAzureTokenExchangeScope = "api://AzureADTokenExchange/.default"
)

// GetAKSTokenSource returns an OAuth2 token source for Azure Kubernetes Service (AKS) authentication.
// It uses the default Azure credentials to obtain a token and creates an OAuth2 token source using the obtained token.
func GetAKSTokenSource(ctx context.Context, audience string) (oauth2.TokenSource, error) {
	options := azidentity.WorkloadIdentityCredentialOptions{}
	if audience == "" {
		audience = defaultAzureTokenExchangeScope
	}

	creds, err := azidentity.NewWorkloadIdentityCredential(&options)
	if err != nil {
		return nil, err
	}

	token, err := creds.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{audience},
	})
	if err != nil {
		return nil, err
	}

	// Create an OAuth2 token source using the assumed role's credentials
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token.Token,
		TokenType:   "Bearer",
		Expiry:      token.ExpiresOn,
	})

	return tokenSource, nil
}

func aksWorkloadIdentityAuth(ctx context.Context, audience string) (*clientAuth, error) {
	azureTokenSource, err := GetAKSTokenSource(ctx, audience)
	if azureTokenSource != nil && err == nil {
		identitiyToken, err := azureTokenSource.Token()
		if err != nil {
			logger.Log.Debug("Error retrieving access token from Azure Workload Identity token source" + err.Error())
			return nil, err
		}

		clientAuth := clientAuth{
			platform:               "azure",
			sessionIdentifier:      fmt.Sprintf("%s-%s", "k8xauth", fmt.Sprint(time.Now().UnixNano()))[:32],
			tokenSource:            &azureTokenSource,
			identityTokenRetriever: identityTokenRetriever{token: []byte(identitiyToken.AccessToken)},
		}
		return &clientAuth, nil
	}
	logger.Log.Debug("Error retrieving AKS Workload Identity token source: " + err.Error())
	return nil, err
}
