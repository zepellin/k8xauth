package auth

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8xauth/internal/logger"
)

func kubernetesTokenPayload(aud, podName string) string {
	exp := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	kubernetes := `{"namespace":"ns","serviceaccount":{"name":"sa"}}`
	if podName != "" {
		kubernetes = `{"namespace":"ns","pod":{"name":"` + podName + `"},"serviceaccount":{"name":"sa"}}`
	}
	return `{"iss":"https://issuer.example.com","sub":"system:serviceaccount:ns:sa","aud":["` + aud + `"],"exp":` + exp + `,"kubernetes.io":` + kubernetes + `}`
}

func TestKubernetesServiceAccountAuth(t *testing.T) {
	token := unsignedJWT(kubernetesTokenPayload("sts.amazonaws.com", "argocd-application-controller-0123456789-abcde"))

	ca, err := kubernetesServiceAccountAuth(context.Background(), writeTokenFile(t, token), "")
	if err != nil {
		t.Fatalf("kubernetesServiceAccountAuth() error = %v", err)
	}
	if ca.platform != "kubernetes" {
		t.Fatalf("platform = %q, want kubernetes", ca.platform)
	}
	if ca.sessionIdentifier != "argocd-application-controller-01" {
		t.Fatalf("sessionIdentifier = %q, want pod name truncated to 32 characters", ca.sessionIdentifier)
	}
	if got, _ := ca.identityTokenRetriever.GetIdentityToken(); string(got) != token {
		t.Fatalf("unexpected identity token: %q", got)
	}
	tk, err := ca.Token()
	if err != nil || tk.AccessToken != token {
		t.Fatalf("Token() = %v, %v", tk, err)
	}
}

func TestKubernetesServiceAccountAuthSessionIdentifierFallback(t *testing.T) {
	path := writeTokenFile(t, unsignedJWT(kubernetesTokenPayload("sts.amazonaws.com", "")))

	t.Setenv("HOSTNAME", "my-pod")
	ca, err := kubernetesServiceAccountAuth(context.Background(), path, "")
	if err != nil {
		t.Fatalf("kubernetesServiceAccountAuth() error = %v", err)
	}
	if ca.sessionIdentifier != "my-pod" {
		t.Fatalf("sessionIdentifier = %q, want HOSTNAME", ca.sessionIdentifier)
	}

	t.Setenv("HOSTNAME", "")
	ca, err = kubernetesServiceAccountAuth(context.Background(), path, "")
	if err != nil {
		t.Fatalf("kubernetesServiceAccountAuth() error = %v", err)
	}
	if ca.sessionIdentifier != "kubernetes" {
		t.Fatalf("sessionIdentifier = %q, want kubernetes", ca.sessionIdentifier)
	}
}

func TestKubernetesServiceAccountAuthAudience(t *testing.T) {
	path := writeTokenFile(t, unsignedJWT(kubernetesTokenPayload("sts.amazonaws.com", "pod")))

	if _, err := kubernetesServiceAccountAuth(context.Background(), path, "sts.amazonaws.com"); err != nil {
		t.Fatalf("matching audience: unexpected error %v", err)
	}

	_, err := kubernetesServiceAccountAuth(context.Background(), path, "api://AzureADTokenExchange")
	if err == nil || !strings.Contains(err.Error(), "api://AzureADTokenExchange") {
		t.Fatalf("mismatched audience: expected audience error, got %v", err)
	}
}

func TestKubernetesServiceAccountAuthMissingFile(t *testing.T) {
	if _, err := kubernetesServiceAccountAuth(context.Background(), filepath.Join(t.TempDir(), "missing"), ""); err == nil {
		t.Fatal("expected an error")
	}
}

func TestNewKubernetesAuthSource(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	token := unsignedJWT(kubernetesTokenPayload("sts.amazonaws.com", "pod"))

	ca, err := New(context.Background(), &Options{AuthType: "kubernetes", TokenFile: writeTokenFile(t, token)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if platform, _ := ca.GetPlatform(); platform != "kubernetes" {
		t.Fatalf("platform = %q, want kubernetes", platform)
	}

	missing := filepath.Join(t.TempDir(), "missing")
	_, err = New(context.Background(), &Options{AuthType: "kubernetes", TokenFile: missing})
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("expected the underlying token file error, got %v", err)
	}

	_, err = New(context.Background(), &Options{AuthType: "kubernetes", TokenFile: writeTokenFile(t, token), Audience: "other"})
	if err == nil || !strings.Contains(err.Error(), `not the requested "other"`) {
		t.Fatalf("expected the underlying audience error, got %v", err)
	}
}

func TestKubernetesServiceAccountAuthShortPodName(t *testing.T) {
	ca, err := kubernetesServiceAccountAuth(context.Background(), writeTokenFile(t, unsignedJWT(kubernetesTokenPayload("sts.amazonaws.com", "a"))), "")
	if err != nil {
		t.Fatalf("kubernetesServiceAccountAuth() error = %v", err)
	}
	if ca.sessionIdentifier != "k8xauth-a" {
		t.Fatalf("sessionIdentifier = %q, want k8xauth-a", ca.sessionIdentifier)
	}
}

func TestNewAllExcludesKubernetesAuthSource(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	// Make sure no cloud provider source can succeed.
	for _, env := range []string{
		"GOOGLE_APPLICATION_CREDENTIALS", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_WEB_IDENTITY_TOKEN_FILE",
		"AZURE_FEDERATED_TOKEN_FILE", "AZURE_CLIENT_ID", "AZURE_TENANT_ID",
	} {
		t.Setenv(env, "")
	}
	t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")
	t.Setenv("HOME", t.TempDir())
	token := unsignedJWT(kubernetesTokenPayload("sts.amazonaws.com", "pod"))

	if ca, err := New(context.Background(), &Options{AuthType: "all", TokenFile: writeTokenFile(t, token)}); err == nil {
		platform, _ := ca.GetPlatform()
		t.Fatalf("expected no source to be found, got platform %q", platform)
	}
}
