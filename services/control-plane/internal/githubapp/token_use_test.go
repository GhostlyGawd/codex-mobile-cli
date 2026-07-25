package githubapp

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type tokenUseClient struct {
	events    *[]string
	token     InstallationToken
	mintErr   error
	revokeErr error
	revoked   string
}

func (c *tokenUseClient) InstallationToken(context.Context, int64, []int64, map[string]string) (InstallationToken, error) {
	*c.events = append(*c.events, "mint")
	return c.token, c.mintErr
}

func (c *tokenUseClient) RevokeInstallationToken(ctx context.Context, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	*c.events = append(*c.events, "revoke")
	c.revoked = token
	return c.revokeErr
}

type tokenUseStore struct {
	events            *[]string
	metadata          TokenUseMetadata
	expires           time.Time
	expiryCalls       int
	expiryFailureCall int
	expiryErr         error
	revoked           bool
}

func (s *tokenUseStore) BeginGitHubInstallationTokenUse(_ context.Context, value TokenUseMetadata) error {
	*s.events = append(*s.events, "reserve")
	s.metadata = value
	return nil
}

func (s *tokenUseStore) SetGitHubInstallationTokenUseExpiry(ctx context.Context, _ string, _ int64, _ string, expires time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	*s.events = append(*s.events, "expiry")
	s.expiryCalls++
	if s.expiryFailureCall == s.expiryCalls {
		return s.expiryErr
	}
	s.expires = expires
	return nil
}

func (s *tokenUseStore) RevokeGitHubInstallationTokenUse(ctx context.Context, _ string, _ int64, _ string, _ time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	*s.events = append(*s.events, "mark")
	s.revoked = true
	return nil
}

func TestInstallationTokenUseReservesBeforeMintAndRevokesBeforeReturn(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	events := []string{}
	client := &tokenUseClient{events: &events, token: InstallationToken{Token: "ephemeral-secret", ExpiresAt: now.Add(time.Hour)}}
	store := &tokenUseStore{events: &events}
	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 64))
	err := useInstallationToken(
		context.Background(), client, store, "owner", 42, []int64{7}, map[string]string{"contents": "write"},
		func(ctx context.Context, token string) error {
			events = append(events, "operation")
			if token != "ephemeral-secret" {
				t.Fatal("operation did not receive the minted token")
			}
			deadline, ok := ctx.Deadline()
			if !ok || deadline.After(time.Now().Add(installationTokenUseTimeout+time.Second)) {
				t.Fatalf("token use deadline = %v (ok=%v)", deadline, ok)
			}
			return nil
		},
		random, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"reserve", "mint", "expiry", "operation", "revoke", "mark"}) {
		t.Fatalf("token lifecycle order = %#v", events)
	}
	if store.metadata.ID == "" || store.metadata.ExpiresAt != now.Add(installationTokenReservationTTL) || store.expires != now.Add(time.Hour) {
		t.Fatalf("durable metadata = %#v expiry=%v", store.metadata, store.expires)
	}
	if client.revoked != "ephemeral-secret" || !store.revoked {
		t.Fatal("successful use did not revoke external and durable token authority")
	}
}

func TestInstallationTokenCleanupRevokesExternallyButPreservesCanceledRemoteAuthority(t *testing.T) {
	now := time.Now().UTC()
	events := []string{}
	client := &tokenUseClient{events: &events, token: InstallationToken{Token: "ephemeral-secret", ExpiresAt: now.Add(time.Hour)}}
	store := &tokenUseStore{events: &events}
	ctx, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	err := useInstallationToken(
		ctx, client, store, "owner", 42, []int64{7}, map[string]string{"contents": "write"},
		func(context.Context, string) error {
			cancel()
			return context.Canceled
		},
		bytes.NewReader(bytes.Repeat([]byte{0x43}, 64)), func() time.Time { return now },
	)
	if !errors.Is(err, context.Canceled) || client.revoked == "" || store.revoked {
		t.Fatalf("canceled token cleanup = err=%v revoked=%q marked=%v", err, client.revoked, store.revoked)
	}
	if !store.expires.After(now) || store.expires.After(now.Add(250*time.Millisecond)) {
		t.Fatalf("canceled remote authority expiry = %v", store.expires)
	}
}

type ambiguousTokenUseError struct{ safeAfter time.Time }

func (e ambiguousTokenUseError) Error() string { return "remote exit is ambiguous" }
func (e ambiguousTokenUseError) GitHubTokenUseSafeAfter() time.Time {
	return e.safeAfter
}

func TestInstallationTokenUseHonorsExplicitRemoteSafeAfter(t *testing.T) {
	now := time.Now().UTC()
	safeAfter := now.Add(90 * time.Millisecond)
	events := []string{}
	client := &tokenUseClient{events: &events, token: InstallationToken{Token: "ephemeral-secret", ExpiresAt: now.Add(time.Hour)}}
	store := &tokenUseStore{events: &events}
	err := useInstallationToken(
		context.Background(), client, store, "owner", 42, []int64{7}, map[string]string{"contents": "write"},
		func(context.Context, string) error { return ambiguousTokenUseError{safeAfter: safeAfter} },
		bytes.NewReader(bytes.Repeat([]byte{0x46}, 64)), func() time.Time { return now },
	)
	var ambiguous tokenUseAmbiguity
	if !errors.As(err, &ambiguous) || client.revoked == "" || store.revoked || !store.expires.Equal(safeAfter) {
		t.Fatalf("explicit remote ambiguity = err=%v revoked=%q marked=%v expiry=%v", err, client.revoked, store.revoked, store.expires)
	}
}

func TestAmbiguousDeadlinePersistenceFailureRetainsProviderExpiry(t *testing.T) {
	now := time.Now().UTC()
	providerExpiry := now.Add(time.Hour)
	safeAfter := now.Add(time.Minute)
	events := []string{}
	client := &tokenUseClient{events: &events, token: InstallationToken{Token: "ephemeral-secret", ExpiresAt: providerExpiry}}
	store := &tokenUseStore{
		events: &events, expiryFailureCall: 2,
		expiryErr: errors.New("metadata update unavailable"),
	}
	err := useInstallationToken(
		context.Background(), client, store, "owner", 42, nil, map[string]string{"contents": "read"},
		func(context.Context, string) error { return ambiguousTokenUseError{safeAfter: safeAfter} },
		bytes.NewReader(bytes.Repeat([]byte{0x47}, 64)), func() time.Time { return now },
	)
	if err == nil || store.revoked || !store.expires.Equal(providerExpiry) || client.revoked == "" {
		t.Fatalf("failed safe-after persistence = err=%v marked=%v expiry=%v provider-revoked=%q", err, store.revoked, store.expires, client.revoked)
	}
}

func TestAmbiguousTokenRevocationLeavesOutstandingMetadata(t *testing.T) {
	now := time.Now().UTC()
	events := []string{}
	client := &tokenUseClient{
		events: &events, token: InstallationToken{Token: "ephemeral-secret", ExpiresAt: now.Add(time.Hour)},
		revokeErr: errors.New("revocation transport unavailable"),
	}
	store := &tokenUseStore{events: &events}
	err := useInstallationToken(
		context.Background(), client, store, "owner", 42, nil, map[string]string{"contents": "read"},
		func(context.Context, string) error { return nil },
		bytes.NewReader(bytes.Repeat([]byte{0x44}, 64)), func() time.Time { return now },
	)
	if err == nil || store.revoked || store.expires != now.Add(time.Hour) {
		t.Fatalf("ambiguous revocation = err=%v marked=%v expiry=%v", err, store.revoked, store.expires)
	}
}

func TestFailedMintClearsConservativeReservation(t *testing.T) {
	now := time.Now().UTC()
	events := []string{}
	client := &tokenUseClient{events: &events, mintErr: errors.New("mint failed")}
	store := &tokenUseStore{events: &events}
	err := useInstallationToken(
		context.Background(), client, store, "owner", 42, nil, map[string]string{"contents": "read"},
		func(context.Context, string) error { t.Fatal("failed mint reached operation"); return nil },
		bytes.NewReader(bytes.Repeat([]byte{0x45}, 64)), func() time.Time { return now },
	)
	if err == nil || !store.revoked || !reflect.DeepEqual(events, []string{"reserve", "mint", "mark"}) {
		t.Fatalf("failed mint lifecycle = err=%v events=%#v marked=%v", err, events, store.revoked)
	}
}
