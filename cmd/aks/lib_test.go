package aks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"k8xauth/internal/auth"

	"golang.org/x/oauth2"
)

type mockTokenProvider struct {
	token             *oauth2.Token
	tokenErr          error
	prettyPrintErr    error
	prettyPrintCalled bool
}

func (m *mockTokenProvider) Token() (*oauth2.Token, error) {
	if m.tokenErr != nil {
		return nil, m.tokenErr
	}
	return m.token, nil
}

func (m *mockTokenProvider) PrettyPrintJWTToken(w io.Writer) error {
	m.prettyPrintCalled = true
	if m.prettyPrintErr != nil {
		return m.prettyPrintErr
	}
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

func TestWriteCredentialsWritesAzureExecCredential(t *testing.T) {
	provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}
	writer := &mockExecCredentialWriter{}
	var output bytes.Buffer

	err := writeCredentials(&auth.Options{}, "client", "tenant", "server", &output, func(*auth.Options) (tokenProvider, error) {
		return provider, nil
	}, func(_ context.Context, _ *oauth2.Token, _, _, _ string) (oauth2.Token, error) {
		return oauth2.Token{AccessToken: "azure-token", Expiry: time.Unix(100, 0)}, nil
	}, writer)
	if err != nil {
		t.Fatalf("writeCredentials() error = %v", err)
	}
	if writer.writtenToken == nil || writer.writtenToken.AccessToken != "azure-token" {
		t.Fatalf("expected exchanged token to be written, got %#v", writer.writtenToken)
	}
	if output.String() != "exec-credential\n" {
		t.Fatalf("unexpected output: %q", output.String())
	}
	if provider.prettyPrintCalled {
		t.Fatal("did not expect source token to be printed")
	}
}

func TestWriteCredentialsReturnsExchangeError(t *testing.T) {
	provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}

	err := writeCredentials(&auth.Options{}, "client", "tenant", "server", &bytes.Buffer{}, func(*auth.Options) (tokenProvider, error) {
		return provider, nil
	}, func(_ context.Context, _ *oauth2.Token, _, _, _ string) (oauth2.Token, error) {
		return oauth2.Token{}, errors.New("exchange-failed")
	}, &mockExecCredentialWriter{})
	if err == nil || !strings.Contains(err.Error(), "failed to exchange source token for Azure credentials") {
		t.Fatalf("expected exchange error, got %v", err)
	}
}

func TestWriteCredentialsReturnsWriterError(t *testing.T) {
	provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}
	writer := &mockExecCredentialWriter{writerErr: errors.New("write-failed")}

	err := writeCredentials(&auth.Options{}, "client", "tenant", "server", &bytes.Buffer{}, func(*auth.Options) (tokenProvider, error) {
		return provider, nil
	}, func(_ context.Context, _ *oauth2.Token, _, _, _ string) (oauth2.Token, error) {
		return oauth2.Token{AccessToken: "azure-token"}, nil
	}, writer)
	if err == nil || !strings.Contains(err.Error(), "failed to write exec credential") {
		t.Fatalf("expected writer error, got %v", err)
	}
}
