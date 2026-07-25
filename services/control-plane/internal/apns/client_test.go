package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendUsesEnvironmentKeyAndGenericPayload(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Unix(1_800_000_000, 0).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/3/device/") || r.Header.Get("apns-topic") != "com.example.mobile" || r.Header.Get("apns-push-type") != "alert" {
			t.Fatalf("unexpected APNs request: %s %#v", r.URL.Path, r.Header)
		}
		token := strings.TrimPrefix(r.Header.Get("authorization"), "bearer ")
		assertJWT(t, token, key, "KEY1", "TEAM1", now.Unix())
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(payload)
		if strings.Contains(string(encoded), "owner/repository") || !strings.Contains(string(encoded), "A session completed.") {
			t.Fatalf("payload must be generic: %s", encoded)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := New(Config{TeamID: "TEAM1", BundleID: "com.example.mobile", ProductionKey: Key{ID: "KEY1", PrivateKey: key}, ProductionURL: server.URL, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	err = client.Send(context.Background(), Production, strings.Repeat("ab", 32), Notification{Kind: "completion", ActivityID: "activity_1", DeepLink: "codex-mobile://activity/activity_1"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSendHandlesUnregisteredAndRetryAfter(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	status := http.StatusGone
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reason := "Unregistered"
		if status == http.StatusTooManyRequests {
			w.Header().Set("retry-after", "7")
			reason = "TooManyRequests"
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"reason":"` + reason + `"}`))
	}))
	defer server.Close()
	client, _ := New(Config{TeamID: "T", BundleID: "b", ProductionKey: Key{ID: "K", PrivateKey: key}, ProductionURL: server.URL})
	err := client.Send(context.Background(), Production, strings.Repeat("ab", 32), Notification{ActivityID: "a"})
	if !errors.Is(err, ErrUnregistered) {
		t.Fatalf("expected unregistered, got %v", err)
	}
	status = http.StatusTooManyRequests
	err = client.Send(context.Background(), Production, strings.Repeat("ab", 32), Notification{ActivityID: "a"})
	var delivery *DeliveryError
	if !errors.As(err, &delivery) || delivery.RetryAfter != 7*time.Second {
		t.Fatalf("expected retry error, got %#v", err)
	}
}

func TestRejectsInvalidDeviceAndSandboxWithoutKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := New(Config{TeamID: "T", BundleID: "b", ProductionKey: Key{ID: "K", PrivateKey: key}})
	if err := client.Send(context.Background(), Production, "not-a-token", Notification{ActivityID: "a"}); err == nil {
		t.Fatal("expected invalid token")
	}
	if err := client.Send(context.Background(), Sandbox, strings.Repeat("ab", 32), Notification{ActivityID: "a"}); err == nil {
		t.Fatal("expected missing sandbox key")
	}
}

func assertJWT(t *testing.T, token string, key *ecdsa.PrivateKey, kid, iss string, iat int64) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT")
	}
	var header map[string]any
	var claims map[string]any
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	c, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(h, &header)
	_ = json.Unmarshal(c, &claims)
	if header["alg"] != "ES256" || header["kid"] != kid || claims["iss"] != iss || int64(claims["iat"].(float64)) != iat {
		t.Fatalf("unexpected JWT metadata: %#v %#v", header, claims)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if len(sig) != 64 {
		t.Fatalf("JWS ES256 signature must be 64 bytes, got %d", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("invalid provider JWT signature")
	}
}
