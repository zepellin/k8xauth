package genericoidc

import (
	"context"
	"fmt"
	"io"
	auth "k8xauth/internal/auth"
	"k8xauth/internal/credwriter"
	"k8xauth/internal/logger"
	"os"

	"golang.org/x/oauth2"
)

type tokenProvider interface {
	Token() (*oauth2.Token, error)
	PrettyPrintJWTToken(w io.Writer) error
}

type execCredentialWriter interface {
	Write(token oauth2.Token, writer ...io.Writer) error
}

func defaultTokenProviderFactory(ctx context.Context, o *auth.Options) (tokenProvider, error) {
	return auth.New(ctx, o)
}

func getCredentials(ctx context.Context, o *auth.Options) {
	err := writeCredentials(ctx, o, os.Stdout, defaultTokenProviderFactory, &credwriter.ExecCredentialWriter{})
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
}

func writeCredentials(ctx context.Context, o *auth.Options, output io.Writer, authFactory func(context.Context, *auth.Options) (tokenProvider, error), writer execCredentialWriter) error {
	authSource, err := authFactory(ctx, o)
	if err != nil {
		return fmt.Errorf("failed to initialize source authentication: %w", err)
	}

	if o.PrintSourceToken {
		if err := authSource.PrettyPrintJWTToken(output); err != nil {
			if logger.Log != nil {
				logger.Log.Warn("Failed to print source token", "error", err.Error())
			}
		}
	}

	identityToken, err := authSource.Token()
	if err != nil {
		return fmt.Errorf("failed to retrieve source token: %w", err)
	}

	if err := writer.Write(*identityToken, output); err != nil {
		return fmt.Errorf("failed to write exec credential: %w", err)
	}

	return nil
}
