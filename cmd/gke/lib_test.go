package gke

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"k8xauth/internal/auth"

	"golang.org/x/oauth2"
)

type mockTokenProvider struct {
	token *oauth2.Token
}

func (m *mockTokenProvider) Token() (*oauth2.Token, error) {
	return m.token, nil
}

func (m *mockTokenProvider) PrettyPrintJWTToken(w io.Writer) error {
	_, err := w.Write([]byte("pretty-token\n"))
	return err
}

type mockExecCredentialWriter struct {
	writtenToken *oauth2.Token
	writerErr    error
}

func (m *mockExecCredentialWriter) Write(token oauth2.Token, writers ...io.Writer) error {
	m.writtenToken = &token
	if m.writerErr != nil {
		return m.writerErr
	}
	if len(writers) > 0 {
		_, err := writers[0].Write([]byte("exec-credential\n"))
		return err
	}
	return nil
}

func TestWriteCredentialsWritesSTSExecCredentialWithoutServiceAccount(t *testing.T) {
	// Inside the bubble time.Now is a fake clock, so the expiry is deterministic.
	synctest.Test(t, func(t *testing.T) {
		provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}
		writer := &mockExecCredentialWriter{}
		start := time.Now()

		err := writeCredentials(t.Context(), &auth.Options{}, "id-provider", "", &bytes.Buffer{}, func(context.Context, *auth.Options) (tokenProvider, error) {
			return provider, nil
		}, func(_ context.Context, identityToken oauth2.Token, idProvider string) (stsExchangeResult, error) {
			if identityToken.AccessToken != "source-token" || idProvider != "id-provider" {
				t.Fatalf("unexpected STS exchange inputs: %q %q", identityToken.AccessToken, idProvider)
			}
			return stsExchangeResult{AccessToken: "sts-token", ExpiresIn: 300}, nil
		}, func(_ context.Context, _ oauth2.Token, _ string) (oauth2.Token, error) {
			return oauth2.Token{}, errors.New("should not be called")
		}, writer)
		if err != nil {
			t.Fatalf("writeCredentials() error = %v", err)
		}
		if writer.writtenToken == nil || writer.writtenToken.AccessToken != "sts-token" {
			t.Fatalf("expected STS token to be written, got %#v", writer.writtenToken)
		}
		if got := writer.writtenToken.Expiry; !got.Equal(start.Add(300 * time.Second)) {
			t.Fatalf("unexpected token expiry: %v", got)
		}
	})
}

func TestWriteCredentialsUsesServiceAccountExchangeWhenConfigured(t *testing.T) {
	provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}
	writer := &mockExecCredentialWriter{}

	err := writeCredentials(t.Context(), &auth.Options{}, "id-provider", "sa@example.com", &bytes.Buffer{}, func(context.Context, *auth.Options) (tokenProvider, error) {
		return provider, nil
	}, func(_ context.Context, _ oauth2.Token, _ string) (stsExchangeResult, error) {
		return stsExchangeResult{AccessToken: "sts-token", ExpiresIn: 300}, nil
	}, func(_ context.Context, stsToken oauth2.Token, serviceAccount string) (oauth2.Token, error) {
		if stsToken.AccessToken != "sts-token" || serviceAccount != "sa@example.com" {
			t.Fatalf("unexpected service account exchange inputs: %q %q", stsToken.AccessToken, serviceAccount)
		}
		return oauth2.Token{AccessToken: "service-account-token"}, nil
	}, writer)
	if err != nil {
		t.Fatalf("writeCredentials() error = %v", err)
	}
	if writer.writtenToken == nil || writer.writtenToken.AccessToken != "service-account-token" {
		t.Fatalf("expected service account token to be written, got %#v", writer.writtenToken)
	}
}

func TestWriteCredentialsReturnsSTSExchangeError(t *testing.T) {
	provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}

	err := writeCredentials(t.Context(), &auth.Options{}, "id-provider", "", &bytes.Buffer{}, func(context.Context, *auth.Options) (tokenProvider, error) {
		return provider, nil
	}, func(_ context.Context, _ oauth2.Token, _ string) (stsExchangeResult, error) {
		return stsExchangeResult{}, errors.New("sts-failed")
	}, func(_ context.Context, _ oauth2.Token, _ string) (oauth2.Token, error) {
		return oauth2.Token{}, nil
	}, &mockExecCredentialWriter{})
	if err == nil || !strings.Contains(err.Error(), "failed to exchange source token with GCP STS") {
		t.Fatalf("expected STS exchange error, got %v", err)
	}
}
