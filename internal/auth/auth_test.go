package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8xauth/internal/logger"

	"golang.org/x/oauth2"
)

// unsignedJWT builds a structurally valid JWT with the given payload. The signature
// is garbage, which is fine because jwtFileTokenSource does not verify it.
func unsignedJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + "." + enc([]byte("sig"))
}

func writeTokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestJWTFileTokenSourceUsesExpClaim(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	token := unsignedJWT(`{"sub":"system:serviceaccount:ns:sa","exp":` + strconv.FormatInt(exp.Unix(), 10) + `}`)

	ts, err := jwtFileTokenSource(writeTokenFile(t, token))
	if err != nil {
		t.Fatalf("jwtFileTokenSource() error = %v", err)
	}
	tk, err := ts.Token()
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if tk.AccessToken != token {
		t.Fatalf("unexpected access token: %q", tk.AccessToken)
	}
	if !tk.Expiry.Equal(exp) {
		t.Fatalf("expiry = %v, want %v", tk.Expiry, exp)
	}
}

func TestJWTFileTokenSourceRejectsBadExpClaim(t *testing.T) {
	for name, payload := range map[string]string{
		"missing":     `{"sub":"x"}`,
		"non-numeric": `{"sub":"x","exp":"tomorrow"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := jwtFileTokenSource(writeTokenFile(t, unsignedJWT(payload))); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

type failingTokenSource struct{}

func (failingTokenSource) Token() (*oauth2.Token, error) {
	return nil, errors.New("token-failed")
}

func TestPrettyPrintJWTTokenReturnsTokenError(t *testing.T) {
	var ts oauth2.TokenSource = failingTokenSource{}
	ca := &clientAuth{tokenSource: &ts}

	err := ca.PrettyPrintJWTToken(io.Discard)
	if err == nil || !strings.Contains(err.Error(), "token-failed") {
		t.Fatalf("expected token error, got %v", err)
	}
}

func TestNormalizeSessionIdentifier(t *testing.T) {
	for in, want := range map[string]string{
		"":   "k8xauth-",
		"a":  "k8xauth-a",
		"ab": "ab",
		"argocd-application-controller-0123456789-abcde": "argocd-application-controller-01",
	} {
		if got := normalizeSessionIdentifier(in); got != want {
			t.Errorf("normalizeSessionIdentifier(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEKSPodIdentityAuthShortHostname(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.23/v1/credentials")
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "")
	t.Setenv("HOSTNAME", "a")

	ca, err := eksPodIdentityAuth(context.Background())
	if err != nil {
		t.Fatalf("eksPodIdentityAuth() error = %v", err)
	}
	if ca.sessionIdentifier != "k8xauth-a" {
		t.Fatalf("sessionIdentifier = %q, want k8xauth-a", ca.sessionIdentifier)
	}
}
