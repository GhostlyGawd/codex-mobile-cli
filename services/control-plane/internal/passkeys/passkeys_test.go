package passkeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestBootstrapIsShortLivedSingleUse(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	m, err := NewBootstrapManagerWithDependencies(
		bytes.Repeat([]byte{1}, 32), time.Minute,
		bytes.NewReader(bytes.Repeat([]byte{2}, 64)), func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := m.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(token); err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(token); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(token); err == nil {
		t.Fatal("consumed bootstrap token remained valid")
	}
}

func TestBootstrapExpires(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	m, _ := NewBootstrapManagerWithDependencies(
		bytes.Repeat([]byte{1}, 32), time.Minute,
		bytes.NewReader(bytes.Repeat([]byte{3}, 64)), func() time.Time { return now },
	)
	token, _, _ := m.Generate()
	now = now.Add(2 * time.Minute)
	if err := m.Validate(token); err == nil {
		t.Fatal("expired bootstrap token accepted")
	}
}

func TestRegistrationAndLoginCeremoniesAreServerSideAndSingleUse(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	randomBytes := make([]byte, 8192)
	for i := range randomBytes {
		randomBytes[i] = byte(i)
	}
	bootstrap, _ := NewBootstrapManagerWithDependencies(
		bytes.Repeat([]byte{4}, 32), 15*time.Minute,
		bytes.NewReader(randomBytes), func() time.Time { return now },
	)
	token, _, _ := bootstrap.Generate()
	service, err := NewService(
		"api.codex.test", "Codex Mobile",
		[]string{"https://api.codex.test"}, NewMemoryStore(), bootstrap,
	)
	if err != nil {
		t.Fatal(err)
	}
	service.random = bytes.NewReader(randomBytes)
	service.now = func() time.Time { return now }
	device := DeviceBinding{InstanceID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), Name: "iPhone"}
	start, err := service.BeginBootstrapRegistration(context.Background(), token, device)
	if err != nil || start.CeremonyID == "" || start.Options == nil || len(start.Options.Response.Challenge) == 0 {
		t.Fatalf("start = %#v, %v", start, err)
	}
	invalid := []byte("{\"invalid\":true}")
	if _, err := service.FinishBootstrapRegistration(context.Background(), start.CeremonyID, token, device, invalid); err == nil {
		t.Fatal("invalid attestation accepted")
	}
	if _, err := service.FinishBootstrapRegistration(context.Background(), start.CeremonyID, token, device, invalid); err == nil {
		t.Fatal("used ceremony accepted twice")
	}
	login, err := service.BeginLogin(context.Background(), device)
	if err != nil || login.CeremonyID == "" || login.Options == nil || len(login.Options.Response.Challenge) == 0 {
		t.Fatalf("login = %#v, %v", login, err)
	}
}

func TestDeviceInstancesResolveToDistinctIDsAndReuseTheSameInstall(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	store.owners["owner"] = Owner{ID: "owner"}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	firstHash := [32]byte{1}
	secondHash := [32]byte{2}
	first, err := store.ResolveDevice(context.Background(), Device{
		ID: "device-a", OwnerID: "owner", Name: "iPhone", Platform: "ios",
		InstanceHash: firstHash, CreatedAt: now, LastSeenAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.ResolveDevice(context.Background(), Device{
		ID: "unused-candidate", OwnerID: "owner", Name: "iPhone", Platform: "ios",
		InstanceHash: firstHash, CreatedAt: now.Add(time.Minute), LastSeenAt: now.Add(time.Minute),
	})
	if err != nil || again.ID != first.ID {
		t.Fatalf("same install was not reused: %#v %v", again, err)
	}
	second, err := store.ResolveDevice(context.Background(), Device{
		ID: "device-b", OwnerID: "owner", Name: "iPad", Platform: "ios",
		InstanceHash: secondHash, CreatedAt: now, LastSeenAt: now,
	})
	if err != nil || second.ID == first.ID {
		t.Fatalf("distinct installs collapsed: first=%#v second=%#v err=%v", first, second, err)
	}
}

func TestRecoveryBootstrapIsBoundToExistingCredentiallessOwner(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	randomBytes := make([]byte, 8192)
	for index := range randomBytes {
		randomBytes[index] = byte(index)
	}
	bootstrapStore := NewMemoryBootstrapStore()
	manager, err := NewBootstrapManagerWithStoreAndDependencies(
		bytes.Repeat([]byte{4}, 32), 15*time.Minute, bootstrapStore,
		bytes.NewReader(randomBytes), func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	token, record, err := manager.NewRecoveryRecord("owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrapStore.Replace(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	store.owners["owner"] = Owner{
		ID: "owner", Handle: bytes.Repeat([]byte{9}, 64), Name: "owner", DisplayName: "Owner",
	}
	service, err := NewService("api.codex.test", "Codex Mobile", []string{"https://api.codex.test"}, store, manager)
	if err != nil {
		t.Fatal(err)
	}
	service.random = bytes.NewReader(randomBytes)
	service.now = func() time.Time { return now }
	device := DeviceBinding{InstanceID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), Name: "Recovery iPhone"}
	start, err := service.BeginBootstrapRegistration(context.Background(), token, device)
	if err != nil || start.CeremonyID == "" || start.Options == nil {
		t.Fatalf("recovery registration did not begin: %#v %v", start, err)
	}
	ceremony := service.ceremonies[start.CeremonyID]
	if ceremony.RecoveryOwner != "owner" || ceremony.Owner.ID != "owner" {
		t.Fatalf("recovery ceremony lost its owner binding: %#v", ceremony)
	}

	firstOwnerStore := NewMemoryBootstrapStore()
	firstOwnerManager, _ := NewBootstrapManagerWithStoreAndDependencies(
		bytes.Repeat([]byte{4}, 32), 15*time.Minute, firstOwnerStore,
		bytes.NewReader(randomBytes), func() time.Time { return now },
	)
	recoveryToken, recoveryRecord, _ := firstOwnerManager.NewRecoveryRecord("missing-owner")
	_ = firstOwnerStore.Replace(context.Background(), recoveryRecord)
	firstOwnerService, _ := NewService("api.codex.test", "Codex Mobile", []string{"https://api.codex.test"}, NewMemoryStore(), firstOwnerManager)
	if _, err := firstOwnerService.BeginBootstrapRegistration(context.Background(), recoveryToken, device); err == nil {
		t.Fatal("owner-bound recovery token was accepted as first-owner bootstrap")
	}
}

func TestAuthenticatedRegistrationExcludesExistingCredentialAndBindsPrincipalDevice(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 13, 0, 0, 0, time.UTC)
	instance := bytes.Repeat([]byte{0x51}, 32)
	binding := DeviceBinding{InstanceID: base64.RawURLEncoding.EncodeToString(instance), Name: "Owner iPhone"}
	owner := Owner{ID: "owner", Handle: bytes.Repeat([]byte{0x31}, 64), Name: "owner", DisplayName: "Owner"}
	first := webauthn.Credential{ID: []byte("credential-one"), PublicKey: []byte{1}}
	store := NewMemoryStore()
	if err := store.CreateOwnerWithCredential(context.Background(), owner, CredentialRecord{
		RPID: "api.codex.test", OwnerID: owner.ID, DeviceID: "device-one", DeviceName: binding.Name,
		DeviceInstanceHash: sha256.Sum256(instance), Credential: first, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := NewBootstrapManagerWithDependencies(
		bytes.Repeat([]byte{1}, 32), time.Minute,
		bytes.NewReader(bytes.Repeat([]byte{2}, 4096)), func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService("api.codex.test", "Codex Mobile", []string{"https://api.codex.test"}, store, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	service.random = bytes.NewReader(bytes.Repeat([]byte{3}, 4096))
	clock := time.Now().UTC()
	service.now = func() time.Time { return clock }

	start, err := service.BeginAdditionalRegistration(context.Background(), owner.ID, "device-one", binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(start.Options.Response.CredentialExcludeList) != 1 ||
		!bytes.Equal(start.Options.Response.CredentialExcludeList[0].CredentialID, first.ID) {
		t.Fatalf("existing credential was not excluded: %#v", start.Options.Response.CredentialExcludeList)
	}

	swapped := DeviceBinding{InstanceID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32)), Name: binding.Name}
	if _, err := service.FinishAdditionalRegistration(context.Background(), start.CeremonyID, owner.ID, "device-one", swapped, []byte(`{"invalid":true}`)); err == nil {
		t.Fatal("device-swapped registration was accepted")
	}
	if _, err := service.FinishAdditionalRegistration(context.Background(), start.CeremonyID, owner.ID, "device-one", binding, []byte(`{"invalid":true}`)); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("device-swapped registration ceremony replay returned %v", err)
	}
	if _, err := service.BeginAdditionalRegistration(context.Background(), "other-owner", "device-one", binding); err == nil {
		t.Fatal("cross-owner registration ceremony was created")
	}
	principalStart, err := service.BeginAdditionalRegistration(context.Background(), owner.ID, "device-one", binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.FinishAdditionalRegistration(context.Background(), principalStart.CeremonyID, "other-owner", "device-one", binding, []byte(`{"invalid":true}`)); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("cross-owner ceremony finish returned %v", err)
	}
	if _, err := service.FinishAdditionalRegistration(context.Background(), principalStart.CeremonyID, owner.ID, "device-one", binding, []byte(`{"invalid":true}`)); err == nil {
		t.Fatal("cross-owner ceremony attempt did not consume the proof")
	}
	expiringStart, err := service.BeginAdditionalRegistration(context.Background(), owner.ID, "device-one", binding)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(ceremonyTTL + time.Second)
	if _, err := service.FinishAdditionalRegistration(context.Background(), expiringStart.CeremonyID, owner.ID, "device-one", binding, []byte(`{"invalid":true}`)); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("expired authenticated registration ceremony returned %v", err)
	}
}

func TestRecoveryCanEnrollSecondCredentialAndFinalCredentialIsProtected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 7, 16, 14, 0, 0, 0, time.UTC)
	instance := bytes.Repeat([]byte{0x61}, 32)
	instanceHash := sha256.Sum256(instance)
	owner := Owner{ID: "owner", Handle: bytes.Repeat([]byte{0x41}, 64), Name: "owner", DisplayName: "Owner"}
	store := NewMemoryStore()
	store.owners[owner.ID] = owner

	first := CredentialRecord{
		RPID: "api.codex.test", OwnerID: owner.ID, DeviceID: "recovery-device", DeviceName: "Recovery iPhone",
		DeviceInstanceHash: instanceHash, Credential: webauthn.Credential{ID: []byte("recovered-credential"), PublicKey: []byte{1}}, CreatedAt: now,
	}
	if err := store.CreateCredentialForRecoveredOwner(ctx, owner, first, RecoveryProof{TokenHash: [32]byte{1}, At: now}); err != nil {
		t.Fatal(err)
	}
	authenticatedOwner, err := store.OwnerForAdditionalCredential(ctx, first.RPID, owner.ID, first.DeviceID, instanceHash)
	if err != nil {
		t.Fatal(err)
	}
	second := CredentialRecord{
		RPID: first.RPID, OwnerID: owner.ID, DeviceID: first.DeviceID, DeviceName: first.DeviceName,
		DeviceInstanceHash: instanceHash, Credential: webauthn.Credential{ID: []byte("second-credential"), PublicKey: []byte{2}}, CreatedAt: now.Add(time.Minute),
	}
	if err := store.CreateAdditionalCredential(ctx, authenticatedOwner, second); err != nil {
		t.Fatal(err)
	}
	values, err := store.ListCredentialMetadata(ctx, first.RPID, owner.ID)
	if err != nil || len(values) != 2 {
		t.Fatalf("second credential was not listed: len=%d err=%v", len(values), err)
	}

	store.owners["other-owner"] = Owner{ID: "other-owner", Handle: bytes.Repeat([]byte{0x42}, 64)}
	if err := store.RevokeCredential(ctx, first.RPID, "other-owner", first.Credential.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner revoke returned %v", err)
	}
	if err := store.RevokeCredential(ctx, first.RPID, owner.ID, second.Credential.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeCredential(ctx, first.RPID, owner.ID, second.Credential.ID); err != nil {
		t.Fatalf("already-revoked credential was not idempotent: %v", err)
	}
	if err := store.RevokeCredential(ctx, first.RPID, owner.ID, first.Credential.ID); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("final credential deletion returned %v", err)
	}
}

func TestConcurrentRevokesCannotDeleteFinalCredential(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 7, 16, 15, 0, 0, 0, time.UTC)
	owner := Owner{ID: "owner", Handle: bytes.Repeat([]byte{0x71}, 64), Name: "owner", DisplayName: "Owner"}
	store := NewMemoryStore()
	first := CredentialRecord{
		RPID: "api.codex.test", OwnerID: owner.ID, DeviceID: "device", DeviceName: "iPhone",
		DeviceInstanceHash: [32]byte{1}, Credential: webauthn.Credential{ID: []byte("one"), PublicKey: []byte{1}}, CreatedAt: now,
	}
	if err := store.CreateOwnerWithCredential(ctx, owner, first); err != nil {
		t.Fatal(err)
	}
	secondOwner := store.ownerLocked(owner.ID)
	second := first
	second.Credential = webauthn.Credential{ID: []byte("two"), PublicKey: []byte{2}}
	if err := store.CreateAdditionalCredential(ctx, secondOwner, second); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for _, credentialID := range [][]byte{first.Credential.ID, second.Credential.ID} {
		credentialID := append([]byte(nil), credentialID...)
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- store.RevokeCredential(ctx, first.RPID, owner.ID, credentialID)
		}()
	}
	wait.Wait()
	close(errorsSeen)
	successes := 0
	preconditions := 0
	for err := range errorsSeen {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, core.ErrPrecondition):
			preconditions++
		default:
			t.Fatalf("unexpected concurrent revoke error: %v", err)
		}
	}
	values, err := store.ListCredentialMetadata(ctx, first.RPID, owner.ID)
	if err != nil || len(values) != 1 || successes != 1 || preconditions != 1 {
		t.Fatalf("concurrent revoke invariant failed: credentials=%d success=%d protected=%d err=%v", len(values), successes, preconditions, err)
	}
}

func TestConcurrentRegistrationAndRevokeAreSerialized(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 7, 16, 15, 30, 0, 0, time.UTC)
	owner := Owner{ID: "owner", Handle: bytes.Repeat([]byte{0x72}, 64), Name: "owner", DisplayName: "Owner"}
	store := NewMemoryStore()
	first := CredentialRecord{
		RPID: "api.codex.test", OwnerID: owner.ID, DeviceID: "device", DeviceName: "iPhone",
		DeviceInstanceHash: [32]byte{1}, Credential: webauthn.Credential{ID: []byte("one"), PublicKey: []byte{1}}, CreatedAt: now,
	}
	if err := store.CreateOwnerWithCredential(ctx, owner, first); err != nil {
		t.Fatal(err)
	}
	authenticatedOwner, err := store.OwnerForAdditionalCredential(ctx, first.RPID, owner.ID, first.DeviceID, first.DeviceInstanceHash)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Credential = webauthn.Credential{ID: []byte("two"), PublicKey: []byte{2}}
	second.CreatedAt = now.Add(time.Second)
	if err := store.CreateAdditionalCredential(ctx, authenticatedOwner, second); err != nil {
		t.Fatal(err)
	}
	third := first
	third.Credential = webauthn.Credential{ID: []byte("three"), PublicKey: []byte{3}}
	third.CreatedAt = now.Add(2 * time.Second)

	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	wait.Add(2)
	go func() {
		defer wait.Done()
		errorsSeen <- store.CreateAdditionalCredential(ctx, authenticatedOwner, third)
	}()
	go func() {
		defer wait.Done()
		errorsSeen <- store.RevokeCredential(ctx, first.RPID, owner.ID, second.Credential.ID)
	}()
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("serialized add/revoke returned %v", err)
		}
	}
	values, err := store.ListCredentialMetadata(ctx, first.RPID, owner.ID)
	if err != nil || len(values) != 2 {
		t.Fatalf("serialized add/revoke invariant failed: credentials=%d err=%v", len(values), err)
	}
}

func TestLoginAdmissionReplacesPerDeviceAndRecoversDeterministically(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 17, 0, 0, 0, time.UTC)
	service := newAdmissionTestService(t, &now, NewMemoryStore())
	device, hash := admissionDevice(1)

	first, err := service.BeginLogin(context.Background(), device)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.BeginLogin(context.Background(), device)
	if err != nil {
		t.Fatalf("legitimate retry was denied: %v", err)
	}
	if len(service.ceremonies) != 1 || service.admission.byActive[hash] != second.CeremonyID {
		t.Fatalf("retry did not replace the prior ceremony: active=%d current=%q", len(service.ceremonies), service.admission.byActive[hash])
	}
	if _, err := service.consume(first.CeremonyID, ceremonyLogin); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("replaced ceremony remained usable: %v", err)
	}
	if _, err := service.consume(second.CeremonyID, ceremonyLogin); err != nil {
		t.Fatal(err)
	}

	for index := 2; index < deviceLoginBurst; index++ {
		start, err := service.BeginLogin(context.Background(), device)
		if err != nil {
			t.Fatalf("retry %d was denied: %v", index+1, err)
		}
		if _, err := service.consume(start.CeremonyID, ceremonyLogin); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.BeginLogin(context.Background(), device); !errors.Is(err, core.ErrCapacity) {
		t.Fatalf("per-device rate limit did not return stable capacity error: %v", err)
	} else if err.Error() != errLoginAdmissionUnavailable.Error() {
		t.Fatalf("per-device limit exposed a distinct error: %q", err)
	}

	now = now.Add(deviceLoginRefillInterval)
	recovered, err := service.BeginLogin(context.Background(), device)
	if err != nil {
		t.Fatalf("device did not recover after one deterministic refill: %v", err)
	}
	if _, err := service.consume(recovered.CeremonyID, ceremonyLogin); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Duration(deviceLoginBurst) * deviceLoginRefillInterval)
	service.mu.Lock()
	service.cleanupAdmissionsLocked(now)
	_, retained := service.admission.byDevice[hash]
	service.mu.Unlock()
	if retained {
		t.Fatal("idle fully-refilled device admission state was not pruned")
	}
}

func TestUnknownLoginFloodCannotConsumeKnownDeviceLane(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 18, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	knownDevice, knownHash := admissionDevice(9000)
	store.devices["known-device"] = Device{ID: "known-device", OwnerID: "owner", Name: knownDevice.Name, Platform: "ios", InstanceHash: knownHash, CreatedAt: now, LastSeenAt: now}
	service := newAdmissionTestService(t, &now, store)

	start := make(chan struct{})
	results := make(chan error, unknownLoginBurst*2)
	var wait sync.WaitGroup
	for index := 0; index < unknownLoginBurst*2; index++ {
		device, _ := admissionDevice(10000 + index)
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := service.BeginLogin(context.Background(), device)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	succeeded, limited := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, core.ErrCapacity):
			if err.Error() != errLoginAdmissionUnavailable.Error() {
				t.Fatalf("global limit exposed a distinct error: %q", err)
			}
			limited++
		default:
			t.Fatalf("unexpected login admission error: %v", err)
		}
	}
	if succeeded != unknownLoginBurst || limited != unknownLoginBurst {
		t.Fatalf("global unknown burst was not exact: success=%d limited=%d", succeeded, limited)
	}
	if service.admission.unknownActive != unknownLoginBurst {
		t.Fatalf("unexpected unknown active count %d", service.admission.unknownActive)
	}

	if _, err := service.BeginLogin(context.Background(), knownDevice); err != nil {
		t.Fatalf("unknown-device flood consumed the reserved known-device lane: %v", err)
	}
	if _, known := service.known[knownHash]; !known {
		t.Fatal("persisted device instance was not silently recognized")
	}

	now = now.Add(unknownLoginRefill)
	newDevice, _ := admissionDevice(20000)
	if _, err := service.BeginLogin(context.Background(), newDevice); err != nil {
		t.Fatalf("unknown global admission did not recover after one refill: %v", err)
	}
}

func TestKnownDeviceLoadFailureIsBackedOffAndRecovers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 18, 30, 0, 0, time.UTC)
	store := &failingKnownDeviceStore{MemoryStore: NewMemoryStore(), err: errors.New("temporary store failure")}
	bootstrap, err := NewBootstrapManagerWithDependencies(
		bytes.Repeat([]byte{1}, 32), time.Minute,
		bytes.NewReader(bytes.Repeat([]byte{2}, 128)), func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService("api.codex.test", "Codex Mobile", []string{"https://api.codex.test"}, store, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	device, _ := admissionDevice(25000)

	if _, err := service.BeginLogin(context.Background(), device); err == nil {
		t.Fatal("known-device store failure was ignored")
	}
	if _, err := service.BeginLogin(context.Background(), device); err == nil {
		t.Fatal("known-device store failure was ignored during backoff")
	}
	if store.calls != 1 {
		t.Fatalf("store failure was retried without backoff: calls=%d", store.calls)
	}
	now = now.Add(knownDeviceLoadRetry)
	store.err = nil
	if _, err := service.BeginLogin(context.Background(), device); err != nil {
		t.Fatalf("known-device load did not recover after backoff: %v", err)
	}
	if store.calls != 2 {
		t.Fatalf("known-device load recovery calls=%d", store.calls)
	}
}

func TestLoginAdmissionReservesCapacityForOwnerCeremonies(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 19, 0, 0, 0, time.UTC)
	service := newAdmissionTestService(t, &now, NewMemoryStore())

	for index := 0; index < maximumLoginCeremonies; index++ {
		_, hash := admissionDevice(30000 + index)
		id := base64.RawURLEncoding.EncodeToString(hash[:])
		value := ceremony{ID: id, Kind: ceremonyLogin, DeviceHash: hash, KnownDevice: true, ExpiresAt: now.Add(ceremonyTTL)}
		service.ceremonies[id] = value
		service.admission.byActive[hash] = id
		service.admission.active++
	}
	newDevice, newHash := admissionDevice(40000)
	_ = newDevice
	if _, err := service.reserveLogin(newHash, true); !errors.Is(err, core.ErrCapacity) {
		t.Fatalf("login traffic exceeded its reserved share: %v", err)
	}
	if err := service.saveCeremony(ceremony{ID: "owner-registration", Kind: ceremonyAdditional}); err != nil {
		t.Fatalf("owner ceremony was starved by login traffic: %v", err)
	}

	for index := 1; index < privilegedCeremonyReserve; index++ {
		id := "owner-reserved-" + base64.RawURLEncoding.EncodeToString([]byte{byte(index >> 8), byte(index)})
		service.ceremonies[id] = ceremony{ID: id, Kind: ceremonyAdditional, ExpiresAt: now.Add(ceremonyTTL)}
	}
	if err := service.saveCeremony(ceremony{ID: "overflow", Kind: ceremonyAdditional}); !errors.Is(err, core.ErrCapacity) {
		t.Fatalf("global ceremony bound was not enforced: %v", err)
	}

	for id, value := range service.ceremonies {
		if value.Kind == ceremonyLogin {
			value.ExpiresAt = now.Add(-time.Second)
			service.ceremonies[id] = value
			break
		}
	}
	if err := service.saveCeremony(ceremony{ID: "after-expiry", Kind: ceremonyAdditional}); err != nil {
		t.Fatalf("expired ceremony did not release bounded capacity: %v", err)
	}
	if len(service.ceremonies) != maximumCeremonies {
		t.Fatalf("unexpected bounded ceremony count %d", len(service.ceremonies))
	}
}

func TestLoginAdmissionDeviceStateBoundRecoversAfterRefill(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 19, 30, 0, 0, time.UTC)
	service := newAdmissionTestService(t, &now, NewMemoryStore())
	for index := 0; index < maximumAdmissionDevices; index++ {
		_, hash := admissionDevice(50000 + index)
		service.admission.byDevice[hash] = &deviceLoginAdmission{
			rate: tokenBucket{tokens: 0, lastRefilled: now},
		}
	}
	_, overflowHash := admissionDevice(60000)
	if _, err := service.reserveLogin(overflowHash, true); !errors.Is(err, core.ErrCapacity) {
		t.Fatalf("admission device-state bound was not enforced: %v", err)
	} else if err.Error() != errLoginAdmissionUnavailable.Error() {
		t.Fatalf("device-state bound exposed a distinct error: %q", err)
	}

	now = now.Add(time.Duration(deviceLoginBurst) * deviceLoginRefillInterval)
	reservation, err := service.reserveLogin(overflowHash, true)
	if err != nil {
		t.Fatalf("admission device-state bound did not recover after refill/prune: %v", err)
	}
	service.cancelLogin(reservation)
	if len(service.admission.byDevice) != 1 {
		t.Fatalf("fully-refilled device states were not pruned: %d retained", len(service.admission.byDevice))
	}
}

func newAdmissionTestService(t *testing.T, now *time.Time, store *MemoryStore) *Service {
	t.Helper()
	bootstrap, err := NewBootstrapManagerWithDependencies(
		bytes.Repeat([]byte{1}, 32), time.Minute,
		bytes.NewReader(bytes.Repeat([]byte{2}, 128)), func() time.Time { return *now },
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService("api.codex.test", "Codex Mobile", []string{"https://api.codex.test"}, store, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return *now }
	return service
}

func admissionDevice(index int) (DeviceBinding, [32]byte) {
	seed := []byte{byte(index >> 24), byte(index >> 16), byte(index >> 8), byte(index)}
	raw := sha256.Sum256(seed)
	return DeviceBinding{InstanceID: base64.RawURLEncoding.EncodeToString(raw[:]), Name: "Test iPhone"}, sha256.Sum256(raw[:])
}

type failingKnownDeviceStore struct {
	*MemoryStore
	err   error
	calls int
}

func (s *failingKnownDeviceStore) KnownDeviceInstanceHashes(ctx context.Context, limit int) ([][32]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.MemoryStore.KnownDeviceInstanceHashes(ctx, limit)
}
