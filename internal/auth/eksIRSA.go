package auth

import (
	"k8xauth/internal/logger"

	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

const (
	SESSION = "IRSA_CREDS_SESSION"
)

func EksAWSIRSATokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	region := os.Getenv("AWS_REGION")
	roleArn := os.Getenv("AWS_ROLE_ARN")
	tokenFilePath := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")

	if region == "" || roleArn == "" || tokenFilePath == "" {
		return nil, errors.New("IRSA environment variables not set")
	}

	token, err := stscreds.IdentityTokenFile(tokenFilePath).GetIdentityToken()
	if err != nil {
		fmt.Printf("error retrieving creds, %v", err)
	}

	t, err := jwt.ParseSigned(string(token), nil) // parse without verification
	if err != nil {
		panic(err)
	}

	var claims map[string]any
	if err := t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		panic(err)
	}

	exp, ok := claims["exp"]
	if !ok {
		panic("no exp")
	}

	// Create an OAuth2 token source using the assumed role's credentials
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: string(token),
		TokenType:   "Bearer",
		Expiry:      time.Unix(int64(exp.(float64)), 0),
	})

	ts := oauth2.ReuseTokenSourceWithExpiry(nil, tokenSource, time.Duration(60*time.Second))

	return ts, nil
}

func eksIRSAAuth(ctx context.Context) (*clientAuth, error) {
	awsTokenSource, err := EksAWSIRSATokenSource(ctx)
	if awsTokenSource != nil && err == nil {
		c := imds.New(imds.Options{})
		i, err := c.GetInstanceIdentityDocument(ctx, nil)
		if err != nil {
			logger.Log.Debug("Couldn't fetch ProjectId from AWS/EKS metadata server")
		}

		identitiyToken, err := awsTokenSource.Token()
		if err != nil {
			logger.Log.Debug("Couldn't fetch identity token from AWS/EKS metadata server")
		}

		clientAuth := clientAuth{
			platform:               "aws",
			sessionIdentifier:      fmt.Sprintf("%s-%s", i.AccountID, i.InstanceID)[:32],
			tokenSource:            &awsTokenSource,
			identityTokenRetriever: identityTokenRetriever{token: []byte(identitiyToken.AccessToken)},
		}
		return &clientAuth, nil
	}
	return nil, err
}
