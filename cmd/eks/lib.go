package eks

import (
	"fmt"
	"io"
	auth "k8xauth/internal/auth"
	"k8xauth/internal/credwriter"
	"k8xauth/internal/logger"

	"context"
	"encoding/base64"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/oauth2"
)

const (
	eksClusterIdHeader = "x-k8s-aws-id" // Header name identifying EKS cluser in STS getCallerIdentity call
	// The sts GetCallerIdentity request is valid for 15 minutes regardless of this parameters value after it has been
	// signed, but we set this unused parameter to 60 for legacy reasons (we check for a value between 0 and 60 on the
	// server side in 0.3.0 or earlier).  IT IS IGNORED.  If we can get STS to support x-amz-expires, then we should
	// set this parameter to the actual expiration, and make it configurable.
	requestPresignParam    = 60
	presignedURLExpiration = 15 * time.Minute // The actual token expiration (presigned STS urls are valid for 15 minutes after timestamp in x-amz-date).
	tokenV1Prefix          = "k8s-aws-v1."    // Prefix of a token in client.authentication.k8s.io/v1beta1 ExecCredential
)

type authSource interface {
	PrettyPrintJWTToken(w io.Writer) error
	GetSessionIdentifier() (string, error)
	GetIdentityToken() ([]byte, error)
}

type execCredentialWriter interface {
	Write(token oauth2.Token, writer ...io.Writer) error
}

type functionAuthSource struct {
	prettyPrint func(io.Writer) error
	sessionID   func() (string, error)
	identity    func() ([]byte, error)
}

type staticIdentityToken []byte

func (s staticIdentityToken) GetIdentityToken() ([]byte, error) {
	return []byte(s), nil
}

func (f *functionAuthSource) PrettyPrintJWTToken(w io.Writer) error {
	return f.prettyPrint(w)
}

func (f *functionAuthSource) GetSessionIdentifier() (string, error) {
	return f.sessionID()
}

func (f *functionAuthSource) GetIdentityToken() ([]byte, error) {
	return f.identity()
}

func defaultAuthSourceFactory(o *auth.Options) (authSource, error) {
	source, err := auth.New(o)
	if err != nil {
		return nil, err
	}

	return &functionAuthSource{
		prettyPrint: source.PrettyPrintJWTToken,
		sessionID:   source.GetSessionIdentifier,
		identity: func() ([]byte, error) {
			identityToken, err := source.IdentityTokenRetriever()
			if err != nil {
				return nil, err
			}
			return identityToken.GetIdentityToken()
		},
	}, nil
}

func getCredentials(o *auth.Options, awsAssumeRoleArn, eksClusterName, stsRegion string) {
	err := writeCredentials(o, awsAssumeRoleArn, eksClusterName, stsRegion, os.Stdout, defaultAuthSourceFactory, buildEKSToken, &credwriter.ExecCredentialWriter{}, time.Now)
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
}

func writeCredentials(
	o *auth.Options,
	awsAssumeRoleArn, eksClusterName, stsRegion string,
	output io.Writer,
	authFactory func(*auth.Options) (authSource, error),
	tokenBuilder func(context.Context, authSource, string, string, string, func() time.Time) (oauth2.Token, error),
	writer execCredentialWriter,
	now func() time.Time,
) error {
	ctx := context.Background()

	authSource, err := authFactory(o)
	if err != nil {
		return fmt.Errorf("failed getting token source: %w", err)
	}

	if o.PrintSourceToken {
		if err := authSource.PrettyPrintJWTToken(output); err != nil {
			if logger.Log != nil {
				logger.Log.Warn("Failed to print source token", "error", err.Error())
			}
		}
	}

	eksToken, err := tokenBuilder(ctx, authSource, awsAssumeRoleArn, eksClusterName, stsRegion, now)
	if err != nil {
		return err
	}

	if err := writer.Write(eksToken, output); err != nil {
		return fmt.Errorf("failed to write exec credential: %w", err)
	}

	return nil
}

func buildEKSToken(ctx context.Context, authSource authSource, awsAssumeRoleArn, eksClusterName, stsRegion string, now func() time.Time) (oauth2.Token, error) {
	sessionIdentifier, err := authSource.GetSessionIdentifier()
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("couldn't retrieve session identifier: %w", err)
	}

	assumeRoleCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(stsRegion))
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("failed to load default AWS config: %w", err)
	}

	identityTokenBytes, err := authSource.GetIdentityToken()
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("failed to get web identity token: %w", err)
	}

	stsAssumeClient := sts.NewFromConfig(assumeRoleCfg)
	awsCredsCache := aws.NewCredentialsCache(stscreds.NewWebIdentityRoleProvider(
		stsAssumeClient,
		awsAssumeRoleArn,
		staticIdentityToken(identityTokenBytes),
		func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = sessionIdentifier
		}),
	)

	awsCredentials, err := awsCredsCache.Retrieve(ctx)
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("couldn't retrieve AWS credentials: %w", err)
	}

	eksSignerCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(stsRegion),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: awsCredentials,
		}),
	)
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("couldn't load AWS config using retrieved credentials: %w", err)
	}

	stsClient := sts.NewFromConfig(eksSignerCfg)
	presignclient := sts.NewPresignClient(stsClient)
	presignedURLString, err := presignclient.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(opt *sts.PresignOptions) {
		opt.Presigner = newCustomHTTPPresignerV4(opt.Presigner, map[string]string{
			eksClusterIdHeader: eksClusterName,
			"X-Amz-Expires":    "60",
		})
	})
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("couldn't presign STS request: %w", err)
	}

	token := tokenV1Prefix + base64.RawURLEncoding.EncodeToString([]byte(presignedURLString.URL))
	tokenExpiration := now().Local().Add(presignedURLExpiration - 1*time.Minute)

	return oauth2.Token{AccessToken: token, Expiry: tokenExpiration}, nil
}

type customHTTPPresignerV4 struct {
	client  sts.HTTPPresignerV4
	headers map[string]string
}

func newCustomHTTPPresignerV4(client sts.HTTPPresignerV4, headers map[string]string) sts.HTTPPresignerV4 {
	return &customHTTPPresignerV4{
		client:  client,
		headers: headers,
	}
}

func (p *customHTTPPresignerV4) PresignHTTP(
	ctx context.Context, credentials aws.Credentials, r *http.Request,
	payloadHash string, service string, region string, signingTime time.Time,
	optFns ...func(*v4.SignerOptions),
) (url string, signedHeader http.Header, err error) {
	for key, val := range p.headers {
		r.Header.Add(key, val)
	}
	return p.client.PresignHTTP(ctx, credentials, r, payloadHash, service, region, signingTime, optFns...)
}
