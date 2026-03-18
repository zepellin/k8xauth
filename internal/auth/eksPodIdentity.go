package auth

import (
	"context"
	"errors"
	"fmt"
	"os"

	"k8xauth/internal/logger"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

	// Load default config which will use Pod Identity credentials
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for Pod Identity: %w", err)
	}

	// Verify we can retrieve credentials
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Pod Identity credentials: %w", err)
	}

	logger.Log.Debug("Successfully retrieved Pod Identity credentials", "accessKeyId", creds.AccessKeyID[:8]+"...")

	// Get caller identity for session identifier
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	// Try to get instance identity for additional context
	var sessionIdentifier string
	imdsClient := imds.New(imds.Options{})
	instanceDoc, err := imdsClient.GetInstanceIdentityDocument(ctx, nil)
	if err == nil {
		sessionIdentifier = fmt.Sprintf("%s-%s", *identity.Account, instanceDoc.InstanceID)
	} else {
		// Fall back to using ARN-based identifier
		sessionIdentifier = fmt.Sprintf("%s-podidentity", *identity.Account)
	}

	// Truncate to 32 chars if needed
	if len(sessionIdentifier) > 32 {
		sessionIdentifier = sessionIdentifier[:32]
	}

	return &clientAuth{
		platform:             "aws",
		sessionIdentifier:    sessionIdentifier,
		hasDirectCredentials: true,
	}, nil
}
