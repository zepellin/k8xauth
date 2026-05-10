package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"k8xauth/internal/logger"

	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// eksPodIdentityAuth attempts to authenticate using EKS Pod Identity.
// Pod Identity provides AWS credentials via a local endpoint, detected by
// AWS_CONTAINER_CREDENTIALS_FULL_URI environment variable.
func eksPodIdentityAuth(ctx context.Context) (*clientAuth, error) {
	// Check for Pod Identity environment variable
	credentialsURI := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
	if credentialsURI == "" {
		return nil, errors.New("Pod Identity environment variables not set")
	}

	logger.Log.Debug("Detected EKS Pod Identity credentials endpoint", "uri", credentialsURI)

	// Derive session identifier from the Kubernetes pod name.
	sessionIdentifier := os.Getenv("HOSTNAME")
	if sessionIdentifier == "" {
		sessionIdentifier = "podidentity"
	}
	if len(sessionIdentifier) > 32 {
		sessionIdentifier = sessionIdentifier[:32]
	}

	ca := &clientAuth{
		platform:             "aws",
		sessionIdentifier:    sessionIdentifier,
		hasDirectCredentials: true,
	}

	// AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE is a Kubernetes projected service account
	// token injected by the EKS Pod Identity webhook alongside the credentials endpoint.
	// It contains a JWT signed by the cluster's OIDC issuer (audience: pods.eks.amazonaws.com)
	// and can be used directly as an OIDC bearer token for generic-oidc consumers.
	if tokenFilePath := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"); tokenFilePath != "" {
		ts, err := jwtFileTokenSource(tokenFilePath)
		if err != nil {
			logger.Log.Debug("Failed to build OIDC token source from Pod Identity authorization token file", "error", err.Error())
		} else {
			rawToken, err := ts.Token()
			if err != nil {
				logger.Log.Debug("Failed to read Pod Identity OIDC token", "error", err.Error())
			} else {
				ca.tokenSource = &ts
				ca.identityTokenRetriever = identityTokenRetriever{token: []byte(rawToken.AccessToken)}
				logger.Log.Debug("Successfully loaded Pod Identity OIDC token from authorization token file")
			}
		}
	}

	return ca, nil
}

// jwtFileTokenSource reads a JWT from tokenFilePath, extracts its expiry from the 'exp' claim,
// and wraps it in an oauth2.TokenSource that refreshes 60 s before expiry.
func jwtFileTokenSource(tokenFilePath string) (oauth2.TokenSource, error) {
	token, err := stscreds.IdentityTokenFile(tokenFilePath).GetIdentityToken()
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	t, err := jwt.ParseSigned(string(token), jwtSignatureAlgorithms) // parse without signature verification
	if err != nil {
		return nil, fmt.Errorf("failed to parse token JWT: %w", err)
	}

	var claims map[string]any
	if err := t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from token: %w", err)
	}

	exp, ok := claims["exp"]
	if !ok {
		return nil, errors.New("token JWT has no exp claim")
	}

	staticTS := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: string(token),
		TokenType:   "Bearer",
		Expiry:      time.Unix(int64(exp.(float64)), 0),
	})

	return oauth2.ReuseTokenSourceWithExpiry(nil, staticTS, 60*time.Second), nil
}
