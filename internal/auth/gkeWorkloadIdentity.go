package auth

import (
	"context"
	"k8xauth/internal/logger"
	"net/http"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
)

const (
	GCP_TOKEN_AUDIENCE = "gcp"
)

// gcpGKETokenSource returns an OAuth2 token source for authenticating with GCP GKE.
// It fetches the GCP default credentials from the environment and uses them to obtain an identity token.
func gcpGKETokenSource(ctx context.Context, audience string) (oauth2.TokenSource, error) {
	credentials, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		logger.Log.Debug("Couldn't fetch GCP default credentials from environment")
		return nil, err
	}

	if audience == "" {
		audience = GCP_TOKEN_AUDIENCE
	}

	ts, err := idtoken.NewTokenSource(ctx, audience, option.WithCredentials(credentials))
	if err != nil {
		logger.Log.Debug("Couldn't fetch GCP identity token")
		return nil, err
	}
	return ts, nil
}

func gkeWorkloadIdentityAuth(ctx context.Context, audience string) (*clientAuth, error) {
	gcpTokenSource, err := gcpGKETokenSource(ctx, audience)
	if gcpTokenSource != nil && err == nil {
		c := metadata.NewClient(&http.Client{})
		projectId, err := c.ProjectIDWithContext(ctx)
		if err != nil {
			logger.Log.Debug("Couldn't fetch ProjectId from GCP metadata server")
		}

		hostname, err := c.HostnameWithContext(ctx)
		if err != nil {
			logger.Log.Debug("Couldn't fetch Hostname from GCP metadata server")
		}

		identityToken, err := gcpTokenSource.Token()
		if err != nil {
			logger.Log.Debug("Couldn't fetch identity token from GCP metadata server", "error", err)
			return nil, err
		}

		sessionIdentifier := projectId + "-" + hostname
		clientAuth := clientAuth{
			platform:               "gcp",
			sessionIdentifier:      sessionIdentifier[:min(len(sessionIdentifier), 32)],
			tokenSource:            &gcpTokenSource,
			identityTokenRetriever: identityTokenRetriever{token: []byte(identityToken.AccessToken)},
		}
		return &clientAuth, nil
	}
	return nil, err
}
