package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"k8xauth/internal/logger"

	"golang.org/x/oauth2"
)

type identityTokenRetriever struct {
	token []byte
}

type clientAuth struct {
	// platform represents the name of the platform.
	// It can be "aws" or "gcp" or "azure"
	platform string

	// sessionIdentifier represents the unique identifier for a session.
	sessionIdentifier string

	// tokenSource represents the source of the OAuth2 token used for authentication.
	tokenSource *oauth2.TokenSource

	// identityTokenRetriever is an interface that defines the method for retrieving an identity token.
	// It is used for AWS EKS IRSA authentication.
	identityTokenRetriever identityTokenRetriever

	// hasDirectCredentials indicates that this auth source provides AWS credentials directly
	// (e.g., EKS Pod Identity) rather than requiring web identity token exchange.
	hasDirectCredentials bool
}

// ClientAuth is an interface that defines the methods for client authentication.
type ClientAuth interface {
	GetPlatform() (string, error)
	GetSessionIdentifier() (string, error)
	New(authSource string) (*clientAuth, error)
	Token() (*oauth2.Token, error)
	IdentityTokenRetriever() (identityTokenRetriever, error)
	PrettyPrintJWTToken() error
}

// New creates a new clientAuth object based on the provided authSourceType.
// It returns the clientAuth object and an error, if any.
func New(options *Options) (*clientAuth, error) {
	ctx := context.Background()

	if options.AuthType == "gke" || options.AuthType == "all" {
		logger.Log.Debug("Source Authentication - Trying GKE Workload Identity")
		clientAuth, err := gkeWorkloadIdentityAuth(ctx, options.Audience)
		if clientAuth != nil && err == nil {
			logger.Log.Debug("Source Authentication - Successfully retrieved GKE Workload Identity token")
			return clientAuth, nil
		}
	}

	if options.AuthType == "eks" || options.AuthType == "all" {
		// Try Pod Identity first (newer method)
		logger.Log.Debug("Source Authentication - Trying EKS Pod Identity")
		clientAuth, err := eksPodIdentityAuth(ctx)
		if clientAuth != nil && err == nil {
			logger.Log.Debug("Source Authentication - Successfully authenticated via EKS Pod Identity")
			return clientAuth, nil
		}

		// Fall back to IRSA
		logger.Log.Debug("Source Authentication - Trying EKS IRSA")
		clientAuth, err = eksIRSAAuth(ctx)
		if clientAuth != nil && err == nil {
			logger.Log.Debug("Source Authentication - Successfully retrieved EKS IRSA token")
			return clientAuth, nil
		}
	}

	if options.AuthType == "aks" || options.AuthType == "all" {
		logger.Log.Debug("Source Authentication - Trying AKS Workload Identity")
		clientAuth, err := aksWorkloadIdentityAuth(ctx, options.Audience)
		if clientAuth != nil && err == nil {
			logger.Log.Debug("Source Authentication - Successfully retrieved AKS Workload Identity token")
			return clientAuth, nil
		}
	}

	return nil, errors.New("no valid authentication source found")
}

// IdentityTokenRetriever returns the identity token retriever for the client authentication.
// It retrieves the identity token used for authentication.
func (ca *clientAuth) IdentityTokenRetriever() (identityTokenRetriever, error) {
	return ca.identityTokenRetriever, nil
}

// GetSessionIdentifier returns the session identifier associated with the client authentication.
// It retrieves the session identifier from the clientAuth struct.
// The session identifier is a string that uniquely identifies the session.
// If there is no session identifier available, it returns an empty string.
func (ac *clientAuth) GetSessionIdentifier() (string, error) {
	return ac.sessionIdentifier, nil
}

// HasDirectCredentials returns true if this auth source provides AWS credentials
// directly (e.g., EKS Pod Identity) rather than requiring web identity token exchange.
func (ac *clientAuth) HasDirectCredentials() bool {
	return ac.hasDirectCredentials
}

// GetPlatform returns the platform associated with the clientAuth instance.
// Possible values are "aws" or "gcp" or "azure"
// It retrieves the platform value stored in the ac.platform field.
// The platform represents the platform on which the client is authenticated.
// It returns the platform value as a string and an error if any.
func (ac *clientAuth) GetPlatform() (string, error) {
	return ac.platform, nil
}

// GetIdentityToken retrieves the identity token.
// It returns the identity token as a byte slice and any error encountered.
func (i identityTokenRetriever) GetIdentityToken() ([]byte, error) {
	return i.token, nil
}

// Token returns the OAuth2 token for the client authentication.
// It retrieves the token from the underlying token source.
func (ac *clientAuth) Token() (*oauth2.Token, error) {
	token, err := (*ac.tokenSource).Token()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (ac *clientAuth) PrettyPrintJWTToken(w io.Writer) error {
	tk, err := (*ac.tokenSource).Token()
	if err != nil {
		logger.Log.Info("Error retrieving token: " + err.Error())
	}
	token := tk.AccessToken

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("error decoding token: JWT must have three parts")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("error decoding token: " + err.Error())
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("error decoding token: " + err.Error())
	}

	m := make(map[string]json.RawMessage)
	m["header"] = header
	m["payload"] = payload
	m["signature"] = []byte(`"` + parts[2] + `"`)

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return errors.New("error marshaling token data")
	}

	_, err = fmt.Fprintln(w, string(b))
	if err != nil {
		return errors.New("error writing token data: " + err.Error())
	}

	return nil
}
