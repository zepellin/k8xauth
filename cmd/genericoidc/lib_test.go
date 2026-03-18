package genericoidc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

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
	writeCalls   int
}

func (m *mockExecCredentialWriter) Write(token oauth2.Token, writers ...io.Writer) error {
	m.writeCalls++
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

func TestWriteCredentialsWritesSourceToken(t *testing.T) {
	provider := &mockTokenProvider{
		token: &oauth2.Token{AccessToken: "source-token"},
	}
	writer := &mockExecCredentialWriter{}
	var output bytes.Buffer

	err := writeCredentials(&auth.Options{}, &output, func(*auth.Options) (tokenProvider, error) {
		return provider, nil
	}, writer)
	if err != nil {
		t.Fatalf("writeCredentials() error = %v", err)
	}

	if provider.prettyPrintCalled {
		t.Fatal("expected PrettyPrintJWTToken not to be called")
	}
	if writer.writeCalls != 1 {
		t.Fatalf("expected writer to be called once, got %d", writer.writeCalls)
	}
	if writer.writtenToken == nil || writer.writtenToken.AccessToken != "source-token" {
		t.Fatalf("expected source token to be written, got %#v", writer.writtenToken)
	}
	if output.String() != "exec-credential\n" {
		t.Fatalf("unexpected output: %q", output.String())
	}
}

func TestWriteCredentialsPrintsSourceTokenWhenEnabled(t *testing.T) {
	provider := &mockTokenProvider{
		token: &oauth2.Token{AccessToken: "source-token"},
	}
	writer := &mockExecCredentialWriter{}
	var output bytes.Buffer

	err := writeCredentials(&auth.Options{PrintSourceToken: true}, &output, func(*auth.Options) (tokenProvider, error) {
		return provider, nil
	}, writer)
	if err != nil {
		t.Fatalf("writeCredentials() error = %v", err)
	}

	if !provider.prettyPrintCalled {
		t.Fatal("expected PrettyPrintJWTToken to be called")
	}
	if output.String() != "pretty-token\nexec-credential\n" {
		t.Fatalf("unexpected output: %q", output.String())
	}
}

func TestWriteCredentialsContinuesWhenPrintingSourceTokenFails(t *testing.T) {
	provider := &mockTokenProvider{
		token:          &oauth2.Token{AccessToken: "source-token"},
		prettyPrintErr: errors.New("print-failed"),
	}
	writer := &mockExecCredentialWriter{}
	var output bytes.Buffer

	err := writeCredentials(&auth.Options{PrintSourceToken: true}, &output, func(*auth.Options) (tokenProvider, error) {
		return provider, nil
	}, writer)
	if err != nil {
		t.Fatalf("writeCredentials() error = %v", err)
	}

	if !provider.prettyPrintCalled {
		t.Fatal("expected PrettyPrintJWTToken to be called")
	}
	if writer.writeCalls != 1 {
		t.Fatalf("expected writer to be called once, got %d", writer.writeCalls)
	}
	if output.String() != "exec-credential\n" {
		t.Fatalf("unexpected output: %q", output.String())
	}
}

func TestWriteCredentialsReturnsAuthInitializationError(t *testing.T) {
	err := writeCredentials(&auth.Options{}, &bytes.Buffer{}, func(*auth.Options) (tokenProvider, error) {
		return nil, errors.New("boom")
	}, &mockExecCredentialWriter{})
	if err == nil || !strings.Contains(err.Error(), "failed to initialize source authentication") {
		t.Fatalf("expected initialization error, got %v", err)
	}
}

func TestWriteCredentialsReturnsTokenError(t *testing.T) {
	provider := &mockTokenProvider{tokenErr: errors.New("token-failed")}

	err := writeCredentials(&auth.Options{}, &bytes.Buffer{}, func(*auth.Options) (tokenProvider, error) {
		return provider, nil
	}, &mockExecCredentialWriter{})
	if err == nil || !strings.Contains(err.Error(), "failed to retrieve source token") {
		t.Fatalf("expected token error, got %v", err)
	}
}

func TestWriteCredentialsReturnsWriterError(t *testing.T) {
	provider := &mockTokenProvider{
		token: &oauth2.Token{AccessToken: "source-token"},
	}
	writer := &mockExecCredentialWriter{writerErr: errors.New("write-failed")}

	err := writeCredentials(&auth.Options{}, &bytes.Buffer{}, func(*auth.Options) (tokenProvider, error) {
		return provider, nil
	}, writer)
	if err == nil || !strings.Contains(err.Error(), "failed to write exec credential") {
		t.Fatalf("expected writer error, got %v", err)
	}
}
