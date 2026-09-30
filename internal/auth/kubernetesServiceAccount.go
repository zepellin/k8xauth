package auth

import (
	"cmp"
	"context"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	// DefaultServiceAccountTokenFile is the path where Kubernetes mounts the pod's service account token.
	DefaultServiceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// kubernetesTokenClaims holds the subset of Kubernetes service account token claims used by k8xauth.
type kubernetesTokenClaims struct {
	jwt.Claims
	Kubernetes struct {
		Pod struct {
			Name string `json:"name"`
		} `json:"pod"`
	} `json:"kubernetes.io"`
}

// kubernetesServiceAccountAuth authenticates using a Kubernetes service account token read from tokenFilePath
// (the default service account token when empty). The token is signed by the cluster's own OIDC issuer, which
// allows any Kubernetes cluster to federate with cloud providers. Its audience is fixed by the token projection,
// so a non-empty audience is only checked against the token rather than requested.
func kubernetesServiceAccountAuth(_ context.Context, tokenFilePath, audience string) (*clientAuth, error) {
	tokenFilePath = cmp.Or(tokenFilePath, DefaultServiceAccountTokenFile)

	tokenSource, err := jwtFileTokenSource(tokenFilePath)
	if err != nil {
		return nil, err
	}

	identityToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}

	t, err := jwt.ParseSigned(identityToken.AccessToken, jwtSignatureAlgorithms) // parse without signature verification
	if err != nil {
		return nil, fmt.Errorf("failed to parse token JWT: %w", err)
	}

	var claims kubernetesTokenClaims
	if err := t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from token: %w", err)
	}

	if audience != "" && !claims.Audience.Contains(audience) {
		return nil, fmt.Errorf("token in %s has audience %v, not the requested %q; the audience is set by the service account token projection", tokenFilePath, []string(claims.Audience), audience)
	}

	// Derive session identifier from the pod the token is bound to.
	sessionIdentifier := cmp.Or(claims.Kubernetes.Pod.Name, os.Getenv("HOSTNAME"), "kubernetes")

	ca := clientAuth{
		platform:               "kubernetes",
		sessionIdentifier:      normalizeSessionIdentifier(sessionIdentifier),
		tokenSource:            &tokenSource,
		identityTokenRetriever: identityTokenRetriever{token: []byte(identityToken.AccessToken)},
	}
	return &ca, nil
}
