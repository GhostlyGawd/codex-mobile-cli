package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.Handler) (*Client, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	client, err := New(12345, pemBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if handler != nil {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		client.baseURL, _ = client.baseURL.Parse(server.URL + "/")
		client.http = server.Client()
	}
	client.now = func() time.Time { return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC) }
	return client, key
}

func TestAppJWTClaimsAndSignature(t *testing.T) {
	t.Parallel()
	client, key := testClient(t, nil)
	token, err := client.AppJWT()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("malformed JWT")
	}
	claimsBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(claimsBytes, &claims)
	if claims["iss"] != "12345" || int64(claims["exp"].(float64)-claims["iat"].(float64)) != 600 {
		t.Fatalf("claims = %#v", claims)
	}
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("JWT signature invalid: %v", err)
	}
}

func TestInstallationTokenAndRepositoryListing(t *testing.T) {
	t.Parallel()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-GitHub-Api-Version") != APIVersion || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing version or authorization headers")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/app/installations/99/access_tokens":
			_, _ = w.Write([]byte("{\"token\":\"installation-secret\",\"expires_at\":\"2026-07-15T13:00:00Z\",\"permissions\":{\"contents\":\"write\"}}"))
		case "/installation/repositories":
			_, _ = w.Write([]byte("{\"repositories\":[{\"id\":7,\"full_name\":\"owner/private\",\"default_branch\":\"main\",\"private\":true,\"updated_at\":\"2026-07-15T00:00:00Z\",\"owner\":{\"type\":\"User\"},\"permissions\":{\"push\":true,\"pull\":true}}]}"))
		default:
			http.NotFound(w, r)
		}
	})
	client, _ := testClient(t, handler)
	token, err := client.InstallationToken(context.Background(), 99, []int64{7}, map[string]string{"contents": "write"})
	if err != nil || token.Token != "installation-secret" {
		t.Fatalf("token = %#v, %v", token, err)
	}
	repos, err := client.ListRepositories(context.Background(), token.Token, 99)
	if err != nil || len(repos) != 1 || repos[0].FullName != "owner/private" || repos[0].Permission != "write" {
		t.Fatalf("repos = %#v, %v", repos, err)
	}
}

func TestRevokeInstallationTokenUsesOfficialEndpointAndAcceptsKnownInvalid(t *testing.T) {
	t.Parallel()
	var calls int
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodDelete || r.URL.Path != "/installation/token" || r.Header.Get("Authorization") != "Bearer installation-secret" {
			t.Fatalf("revocation request = %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		if calls == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
	})
	client, _ := testClient(t, handler)
	if err := client.RevokeInstallationToken(context.Background(), "installation-secret"); err != nil {
		t.Fatal(err)
	}
	if err := client.RevokeInstallationToken(context.Background(), "installation-secret"); err != nil {
		t.Fatalf("already-invalid token revocation = %v", err)
	}
}

func TestInstallationOwnershipRejectsSuspendedInstallation(t *testing.T) {
	t.Parallel()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{\"id\":99,\"suspended_at\":\"2026-07-15T12:00:00Z\"}"))
	})
	client, _ := testClient(t, handler)
	if err := client.VerifyInstallationOwnership(context.Background(), "user-token", 99); err == nil {
		t.Fatal("suspended installation accepted")
	}
}

func TestTokenBrokerReturnsWipeableCopyWithoutMaterializingAFile(t *testing.T) {
	t.Parallel()
	broker := TokenBroker{Token: "secret-token"}
	credential, cleanup, err := broker.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(credential) != "secret-token" {
		t.Fatal("credential copy mismatch")
	}
	cleanup()
	for _, value := range credential {
		if value != 0 {
			t.Fatal("credential copy survived cleanup")
		}
	}
}
