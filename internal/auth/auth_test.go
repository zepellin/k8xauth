package auth

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
