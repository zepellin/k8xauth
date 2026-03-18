package eks

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

type mockAuthSource struct {
	prettyPrintCalled bool
	prettyPrintErr    error
	sessionID         string
	sessionErr        error
	identityToken     []byte
	identityErr       error
}

func (m *mockAuthSource) PrettyPrintJWTToken(w io.Writer) error {
	m.prettyPrintCalled = true
	if m.prettyPrintErr != nil {
		return m.prettyPrintErr
	}
	_, err := w.Write([]byte("pretty-token\n"))
	return err
}

func (m *mockAuthSource) GetSessionIdentifier() (string, error) {
	if m.sessionErr != nil {
		return "", m.sessionErr
	}
	return m.sessionID, nil
}

func (m *mockAuthSource) GetIdentityToken() ([]byte, error) {
	if m.identityErr != nil {
		return nil, m.identityErr
	}
	return m.identityToken, nil
}

func (m *mockAuthSource) HasDirectCredentials() bool {
	return false
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

func TestWriteCredentialsWritesEKSToken(t *testing.T) {
	source := &mockAuthSource{sessionID: "session", identityToken: []byte("jwt")}
	writer := &mockExecCredentialWriter{}
	var output bytes.Buffer

	err := writeCredentials(&auth.Options{}, "role", "cluster", "us-east-1", &output, func(*auth.Options) (authSource, error) {
		return source, nil
	}, func(_ context.Context, providedSource authSource, roleArn, clusterName, region string, _ func() time.Time) (oauth2.Token, error) {
		if roleArn != "role" || clusterName != "cluster" || region != "us-east-1" {
			t.Fatal("unexpected token builder inputs")
		}
		return oauth2.Token{AccessToken: "eks-token"}, nil
	}, writer, time.Now)
	if err != nil {
		t.Fatalf("writeCredentials() error = %v", err)
	}
	if writer.writtenToken == nil || writer.writtenToken.AccessToken != "eks-token" {
		t.Fatalf("expected EKS token to be written, got %#v", writer.writtenToken)
	}
	if output.String() != "exec-credential\n" {
		t.Fatalf("unexpected output: %q", output.String())
	}
}

func TestWriteCredentialsReturnsTokenBuilderError(t *testing.T) {
	source := &mockAuthSource{sessionID: "session", identityToken: []byte("jwt")}

	err := writeCredentials(&auth.Options{}, "role", "cluster", "us-east-1", &bytes.Buffer{}, func(*auth.Options) (authSource, error) {
		return source, nil
	}, func(_ context.Context, _ authSource, _, _, _ string, _ func() time.Time) (oauth2.Token, error) {
		return oauth2.Token{}, errors.New("builder-failed")
	}, &mockExecCredentialWriter{}, time.Now)
	if err == nil || !strings.Contains(err.Error(), "builder-failed") {
		t.Fatalf("expected builder error, got %v", err)
	}
}

func TestBuildEKSTokenReturnsSessionIdentifierError(t *testing.T) {
	source := &mockAuthSource{sessionErr: errors.New("session-failed")}

	_, err := buildEKSToken(nil, source, "role", "cluster", "us-east-1", time.Now)
	if err == nil || !strings.Contains(err.Error(), "couldn't retrieve session identifier") {
		t.Fatalf("expected session identifier error, got %v", err)
	}
}
