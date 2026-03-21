package auth

import (
	"context"
	"errors"
	"os"
	"strings"

	"golang.org/x/oauth2"
)

// irsaTokenSource builds an oauth2.TokenSource from the web identity token file used by
// EKS IRSA (IAM Roles for Service Accounts).
func irsaTokenSource(_ context.Context) (oauth2.TokenSource, error) {
	region := os.Getenv("AWS_REGION")
	roleARN := os.Getenv("AWS_ROLE_ARN")
	tokenFilePath := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")

	if region == "" || roleARN == "" || tokenFilePath == "" {
		return nil, errors.New("IRSA environment variables not set")
	}

	return jwtFileTokenSource(tokenFilePath)
}

func eksIRSAAuth(ctx context.Context) (*clientAuth, error) {
	awsTokenSource, err := irsaTokenSource(ctx)
	if err != nil {
		return nil, err
	}

	identityToken, err := awsTokenSource.Token()
	if err != nil {
		return nil, err
	}

	// Derive session identifier from the role name (last "/"-delimited segment of the ARN).
	roleARN := os.Getenv("AWS_ROLE_ARN")
	sessionIdentifier := roleARN
	if idx := strings.LastIndex(roleARN, "/"); idx >= 0 {
		sessionIdentifier = roleARN[idx+1:]
	}
	if len(sessionIdentifier) > 32 {
		sessionIdentifier = sessionIdentifier[:32]
	}

	ca := clientAuth{
		platform:               "aws",
		sessionIdentifier:      sessionIdentifier,
		tokenSource:            &awsTokenSource,
		identityTokenRetriever: identityTokenRetriever{token: []byte(identityToken.AccessToken)},
	}
	return &ca, nil
}
