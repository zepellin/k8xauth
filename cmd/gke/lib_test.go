package gke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"k8xauth/internal/auth"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
)

const (
	testSTSURL           = "https://sts.test/v1/token"
	testImpersonationURL = "https://iamcredentials.test/v1/projects/-/serviceAccounts/sa@example.com:generateAccessToken"
	testAudience         = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider"
)

type mockTokenProvider struct {
	token *oauth2.Token
	err   error
}

func (m *mockTokenProvider) Token() (*oauth2.Token, error) {
	return m.token, m.err
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

// handlerTransport serves requests in memory, so no sockets are opened inside synctest bubbles.
type handlerTransport struct {
	handler http.Handler
}

func (h handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// fakeGCP emulates the GCP STS token exchange and IAM Credentials generateAccessToken endpoints.
type fakeGCP struct {
	t                   *testing.T
	stsStatus           int
	impersonationExpiry time.Time
	impersonationCalled bool
}

func (f *fakeGCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.String() {
	case testSTSURL:
		if err := r.ParseForm(); err != nil {
			f.t.Fatalf("failed to parse STS request: %v", err)
		}
		if got := r.Form.Get("subject_token"); got != "source-token" {
			f.t.Errorf("unexpected subject_token: %q", got)
		}
		if got := r.Form.Get("audience"); got != testAudience {
			f.t.Errorf("unexpected audience: %q", got)
		}
		if got := r.Form.Get("subject_token_type"); got != SUBJECT_TOKEN_TYPE {
			f.t.Errorf("unexpected subject_token_type: %q", got)
		}
		if got := r.Form.Get("scope"); got != SCOPE {
			f.t.Errorf("unexpected scope: %q", got)
		}
		if f.stsStatus != 0 {
			http.Error(w, "sts-failed", f.stsStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "sts-token",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        300,
		})
	case testImpersonationURL:
		f.impersonationCalled = true
		if got := r.Header.Get("Authorization"); got != "Bearer sts-token" {
			f.t.Errorf("unexpected impersonation Authorization header: %q", got)
		}
		var body struct {
			Scope []string `json:"scope"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Fatalf("failed to decode impersonation request: %v", err)
		}
		if len(body.Scope) != 1 || body.Scope[0] != SCOPE {
			f.t.Errorf("unexpected impersonation scope: %v", body.Scope)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accessToken": "service-account-token",
			"expireTime":  f.impersonationExpiry.Format(time.RFC3339),
		})
	default:
		f.t.Errorf("unexpected request to %s", r.URL)
		http.NotFound(w, r)
	}
}

func contextWithFakeGCP(ctx context.Context, f *fakeGCP) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: handlerTransport{handler: f}})
}

func testConfig(serviceAccountImpersonationURL string) externalaccount.Config {
	return externalaccount.Config{
		Audience:                       testAudience,
		SubjectTokenType:               SUBJECT_TOKEN_TYPE,
		TokenURL:                       testSTSURL,
		ServiceAccountImpersonationURL: serviceAccountImpersonationURL,
		Scopes:                         []string{SCOPE},
	}
}

func staticAuthFactory(provider tokenProvider) func(context.Context, *auth.Options) (tokenProvider, error) {
	return func(context.Context, *auth.Options) (tokenProvider, error) {
		return provider, nil
	}
}

func TestNewExternalAccountConfig(t *testing.T) {
	conf := newExternalAccountConfig("123", "pool", "provider", "")
	if conf.Audience != testAudience {
		t.Fatalf("unexpected audience: %q", conf.Audience)
	}
	if conf.SubjectTokenType != SUBJECT_TOKEN_TYPE {
		t.Fatalf("unexpected subject token type: %q", conf.SubjectTokenType)
	}
	if len(conf.Scopes) != 1 || conf.Scopes[0] != SCOPE {
		t.Fatalf("unexpected scopes: %v", conf.Scopes)
	}
	if conf.ServiceAccountImpersonationURL != "" {
		t.Fatalf("expected no impersonation URL, got %q", conf.ServiceAccountImpersonationURL)
	}

	conf = newExternalAccountConfig("123", "pool", "provider", "sa@example.com")
	want := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@example.com:generateAccessToken"
	if conf.ServiceAccountImpersonationURL != want {
		t.Fatalf("unexpected impersonation URL: %q", conf.ServiceAccountImpersonationURL)
	}
}

func TestWriteCredentialsWritesSTSExecCredentialWithoutServiceAccount(t *testing.T) {
	// Inside the bubble time.Now is a fake clock, so the expiry is deterministic.
	synctest.Test(t, func(t *testing.T) {
		gcp := &fakeGCP{t: t}
		provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}
		writer := &mockExecCredentialWriter{}
		start := time.Now()

		err := writeCredentials(contextWithFakeGCP(t.Context(), gcp), &auth.Options{}, testConfig(""), &bytes.Buffer{}, staticAuthFactory(provider), writer)
		if err != nil {
			t.Fatalf("writeCredentials() error = %v", err)
		}
		if gcp.impersonationCalled {
			t.Fatal("expected no service account impersonation")
		}
		if writer.writtenToken == nil || writer.writtenToken.AccessToken != "sts-token" {
			t.Fatalf("expected STS token to be written, got %#v", writer.writtenToken)
		}
		if got := writer.writtenToken.Expiry; !got.Equal(start.Add(300 * time.Second)) {
			t.Fatalf("unexpected token expiry: %v", got)
		}
	})
}

func TestWriteCredentialsUsesServiceAccountImpersonationWhenConfigured(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	gcp := &fakeGCP{t: t, impersonationExpiry: expiry}
	provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}
	writer := &mockExecCredentialWriter{}

	err := writeCredentials(contextWithFakeGCP(t.Context(), gcp), &auth.Options{}, testConfig(testImpersonationURL), &bytes.Buffer{}, staticAuthFactory(provider), writer)
	if err != nil {
		t.Fatalf("writeCredentials() error = %v", err)
	}
	if writer.writtenToken == nil || writer.writtenToken.AccessToken != "service-account-token" {
		t.Fatalf("expected service account token to be written, got %#v", writer.writtenToken)
	}
	if got := writer.writtenToken.Expiry; !got.Equal(expiry) {
		t.Fatalf("expected service account token expiry %v, got %v", expiry, got)
	}
}

func TestWriteCredentialsPrintsSourceToken(t *testing.T) {
	gcp := &fakeGCP{t: t}
	provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}
	output := &bytes.Buffer{}

	err := writeCredentials(contextWithFakeGCP(t.Context(), gcp), &auth.Options{PrintSourceToken: true}, testConfig(""), output, staticAuthFactory(provider), &mockExecCredentialWriter{})
	if err != nil {
		t.Fatalf("writeCredentials() error = %v", err)
	}
	if got := output.String(); got != "pretty-token\nexec-credential\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestWriteCredentialsReturnsAuthFactoryError(t *testing.T) {
	err := writeCredentials(t.Context(), &auth.Options{}, testConfig(""), &bytes.Buffer{}, func(context.Context, *auth.Options) (tokenProvider, error) {
		return nil, errors.New("factory-failed")
	}, &mockExecCredentialWriter{})
	if err == nil || !strings.Contains(err.Error(), "failed to initialize source authentication") {
		t.Fatalf("expected auth factory error, got %v", err)
	}
}

func TestWriteCredentialsReturnsSourceTokenError(t *testing.T) {
	provider := &mockTokenProvider{err: errors.New("source-failed")}

	err := writeCredentials(contextWithFakeGCP(t.Context(), &fakeGCP{t: t}), &auth.Options{}, testConfig(""), &bytes.Buffer{}, staticAuthFactory(provider), &mockExecCredentialWriter{})
	if err == nil || !strings.Contains(err.Error(), "failed to retrieve source token") {
		t.Fatalf("expected source token error, got %v", err)
	}
}

func TestWriteCredentialsReturnsSTSExchangeError(t *testing.T) {
	gcp := &fakeGCP{t: t, stsStatus: http.StatusUnauthorized}
	provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}

	err := writeCredentials(contextWithFakeGCP(t.Context(), gcp), &auth.Options{}, testConfig(""), &bytes.Buffer{}, staticAuthFactory(provider), &mockExecCredentialWriter{})
	if err == nil || !strings.Contains(err.Error(), "failed to exchange source token for GCP access token") {
		t.Fatalf("expected STS exchange error, got %v", err)
	}
}

func TestWriteCredentialsReturnsWriterError(t *testing.T) {
	gcp := &fakeGCP{t: t}
	provider := &mockTokenProvider{token: &oauth2.Token{AccessToken: "source-token"}}

	err := writeCredentials(contextWithFakeGCP(t.Context(), gcp), &auth.Options{}, testConfig(""), &bytes.Buffer{}, staticAuthFactory(provider), &mockExecCredentialWriter{writerErr: errors.New("write-failed")})
	if err == nil || !strings.Contains(err.Error(), "failed to write exec credential") {
		t.Fatalf("expected writer error, got %v", err)
	}
}
