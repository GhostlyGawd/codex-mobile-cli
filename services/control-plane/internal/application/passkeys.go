package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/passkeys"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/go-webauthn/webauthn/protocol"
)

func (a *Application) GetCapabilities(ctx context.Context) (httpapi.ClientCapabilities, error) {
	available, err := a.deps.Bootstrap.Available(ctx)
	if err != nil {
		return httpapi.ClientCapabilities{}, err
	}
	return httpapi.ClientCapabilities{
		GitHubConfigured:             a.config.GitHubConfigured,
		PasskeyBootstrapAvailable:    available,
		APNSConfigured:               a.config.APNSConfigured,
		PreviewsConfigured:           a.config.PreviewsConfigured,
		StructuredApprovalsAvailable: true,
		MaximumRunningWorkspaces:     a.config.MaximumRunningWorkspaces,
	}, nil
}

func (a *Application) BeginPasskeyRegistration(ctx context.Context, request httpapi.BootstrapRegistrationRequest) (httpapi.PasskeyRegistrationChallenge, error) {
	device := passkeys.DeviceBinding{InstanceID: request.DeviceInstanceID, Name: request.DeviceName}
	start, err := a.deps.Passkeys.BeginBootstrapRegistration(ctx, request.BootstrapToken, device)
	if err != nil {
		return httpapi.PasskeyRegistrationChallenge{}, unauthorized(err)
	}
	challenge, err := registrationChallenge(start)
	if err != nil {
		return httpapi.PasskeyRegistrationChallenge{}, external(err)
	}
	return challenge, nil
}

func (a *Application) FinishPasskeyRegistration(ctx context.Context, credential httpapi.PasskeyRegistrationCredential) (httpapi.SessionTokens, error) {
	response, err := registrationCredentialJSON(credential)
	if err != nil {
		return httpapi.SessionTokens{}, invalid(err)
	}
	device := passkeys.DeviceBinding{InstanceID: credential.DeviceInstanceID, Name: credential.DeviceName}
	result, err := a.deps.Passkeys.FinishBootstrapRegistration(ctx, credential.CeremonyID, "", device, response)
	zero(response)
	if err != nil {
		return httpapi.SessionTokens{}, unauthorized(err)
	}
	pair, err := a.deps.Sessions.Issue(ctx, result.OwnerID, result.DeviceID)
	if err != nil {
		return httpapi.SessionTokens{}, err
	}
	a.audit(httpapi.Principal{OwnerID: result.OwnerID, DeviceID: result.DeviceID}, "", "passkey.bootstrap_enroll", "success", "device", result.DeviceID, nil)
	return sessionTokens(pair, result.DeviceID), nil
}

func (a *Application) BeginPasskeyAuthentication(ctx context.Context, request httpapi.DeviceIdentityRequest) (httpapi.PasskeyAuthenticationChallenge, error) {
	start, err := a.deps.Passkeys.BeginLogin(ctx, passkeys.DeviceBinding{InstanceID: request.DeviceInstanceID, Name: request.DeviceName})
	if err != nil {
		return httpapi.PasskeyAuthenticationChallenge{}, err
	}
	return authenticationChallenge(start)
}

func (a *Application) FinishPasskeyAuthentication(ctx context.Context, credential httpapi.PasskeyAssertionCredential) (httpapi.SessionTokens, error) {
	response, err := assertionCredentialJSON(credential)
	if err != nil {
		return httpapi.SessionTokens{}, invalid(err)
	}
	device := passkeys.DeviceBinding{InstanceID: credential.DeviceInstanceID, Name: credential.DeviceName}
	result, err := a.deps.Passkeys.FinishLogin(ctx, credential.CeremonyID, device, response)
	zero(response)
	if err != nil {
		return httpapi.SessionTokens{}, unauthorized(err)
	}
	pair, err := a.deps.Sessions.Issue(ctx, result.OwnerID, result.DeviceID)
	if err != nil {
		return httpapi.SessionTokens{}, err
	}
	a.audit(httpapi.Principal{OwnerID: result.OwnerID, DeviceID: result.DeviceID}, "", "passkey.authenticate", "success", "device", result.DeviceID, nil)
	return sessionTokens(pair, result.DeviceID), nil
}

func (a *Application) BeginAdditionalPasskeyRegistration(ctx context.Context, principal httpapi.Principal, request httpapi.DeviceIdentityRequest) (httpapi.PasskeyRegistrationChallenge, error) {
	device := passkeys.DeviceBinding{InstanceID: request.DeviceInstanceID, Name: request.DeviceName}
	start, err := a.deps.Passkeys.BeginAdditionalRegistration(ctx, principal.OwnerID, principal.DeviceID, device)
	if err != nil {
		return httpapi.PasskeyRegistrationChallenge{}, err
	}
	challenge, err := registrationChallenge(start)
	if err != nil {
		return httpapi.PasskeyRegistrationChallenge{}, external(err)
	}
	return challenge, nil
}

func (a *Application) FinishAdditionalPasskeyRegistration(ctx context.Context, principal httpapi.Principal, credential httpapi.PasskeyRegistrationCredential) (httpapi.PasskeyMetadata, error) {
	response, err := registrationCredentialJSON(credential)
	if err != nil {
		return httpapi.PasskeyMetadata{}, invalid(err)
	}
	device := passkeys.DeviceBinding{InstanceID: credential.DeviceInstanceID, Name: credential.DeviceName}
	metadata, err := a.deps.Passkeys.FinishAdditionalRegistration(ctx, credential.CeremonyID, principal.OwnerID, principal.DeviceID, device, response)
	zero(response)
	if err != nil {
		return httpapi.PasskeyMetadata{}, err
	}
	value := passkeyMetadata(metadata)
	a.audit(principal, "", "passkey.add", "success", "passkey", value.ID, map[string]any{"device_name": value.DeviceName})
	return value, nil
}

func (a *Application) ListPasskeys(ctx context.Context, principal httpapi.Principal) ([]httpapi.PasskeyMetadata, error) {
	values, err := a.deps.Passkeys.ListCredentials(ctx, principal.OwnerID)
	if err != nil {
		return nil, err
	}
	result := make([]httpapi.PasskeyMetadata, 0, len(values))
	for _, value := range values {
		result = append(result, passkeyMetadata(value))
	}
	return result, nil
}

func (a *Application) RevokePasskey(ctx context.Context, principal httpapi.Principal, credentialID string) error {
	if err := a.deps.Passkeys.RevokeCredential(ctx, principal.OwnerID, credentialID); err != nil {
		return err
	}
	a.audit(principal, "", "passkey.revoke", "success", "passkey", credentialID, nil)
	return nil
}

func passkeyMetadata(value passkeys.CredentialMetadata) httpapi.PasskeyMetadata {
	return httpapi.PasskeyMetadata{
		ID: base64.RawURLEncoding.EncodeToString(value.CredentialID), DeviceName: value.DeviceName,
		CreatedAt: value.CreatedAt, LastUsedAt: value.LastUsedAt,
	}
}

func (a *Application) RefreshSession(ctx context.Context, request httpapi.RefreshSessionRequest) (httpapi.SessionTokens, error) {
	refreshPrincipal, err := a.deps.Sessions.RefreshPrincipal(ctx, request.RefreshToken)
	if err != nil {
		return httpapi.SessionTokens{}, unauthorized(err)
	}
	releaseAdmission := a.acquireTerminalAdmission(refreshPrincipal.OwnerID, refreshPrincipal.DeviceID)
	defer releaseAdmission()
	pair, err := a.deps.Sessions.Rotate(ctx, request.RefreshToken)
	if err != nil {
		if errors.Is(err, session.ErrReplay) {
			disconnected := a.deps.Terminals.RevokeDevice(refreshPrincipal.OwnerID, refreshPrincipal.DeviceID)
			previewGrantsRevoked := 0
			if a.deps.PreviewTokens != nil {
				previewGrantsRevoked = a.deps.PreviewTokens.RevokeDevice(refreshPrincipal.OwnerID, refreshPrincipal.DeviceID)
			}
			a.audit(httpapi.Principal{
				OwnerID: refreshPrincipal.OwnerID, DeviceID: refreshPrincipal.DeviceID, FamilyID: refreshPrincipal.FamilyID,
			}, "", "session.refresh_replay", "denied", "session_family", refreshPrincipal.FamilyID, map[string]any{
				"terminal_connections_revoked": disconnected, "preview_grants_revoked": previewGrantsRevoked,
				"security_action": "session_family_revoked",
			})
			return httpapi.SessionTokens{}, err
		}
		return httpapi.SessionTokens{}, unauthorized(err)
	}
	principal, err := a.deps.Sessions.Authenticate(ctx, pair.AccessToken)
	if err != nil {
		return httpapi.SessionTokens{}, fmt.Errorf("validate rotated session: %w", err)
	}
	if principal.DeviceID == "" {
		return httpapi.SessionTokens{}, errors.New("validate rotated session: device identity is missing")
	}
	return sessionTokens(pair, principal.DeviceID), nil
}

func (a *Application) RevokeCurrentSession(ctx context.Context, principal httpapi.Principal) error {
	if principal.FamilyID == "" {
		return unauthorized(errors.New("session family is unavailable"))
	}
	releaseAdmission := a.acquireTerminalAdmission(principal.OwnerID, principal.DeviceID)
	defer releaseAdmission()
	if err := a.deps.Sessions.RevokeFamily(ctx, principal.FamilyID); err != nil {
		return err
	}
	disconnected := a.deps.Terminals.RevokeDevice(principal.OwnerID, principal.DeviceID)
	previewGrantsRevoked := 0
	if a.deps.PreviewTokens != nil {
		previewGrantsRevoked = a.deps.PreviewTokens.RevokeDevice(principal.OwnerID, principal.DeviceID)
	}
	a.audit(principal, "", "session.revoke", "success", "session_family", principal.FamilyID, map[string]any{
		"terminal_connections_revoked": disconnected, "preview_grants_revoked": previewGrantsRevoked,
	})
	return nil
}

func (a *Application) ListDevices(ctx context.Context, principal httpapi.Principal) ([]httpapi.DeviceSummary, error) {
	values, err := a.deps.Sessions.ListDevices(ctx, principal.OwnerID)
	if err != nil {
		return nil, err
	}
	result := make([]httpapi.DeviceSummary, 0, len(values))
	for _, value := range values {
		result = append(result, httpapi.DeviceSummary{
			ID: value.ID, Name: value.Name, Platform: value.Platform, Current: value.ID == principal.DeviceID,
			CreatedAt: value.CreatedAt, LastSeenAt: value.LastSeenAt,
		})
	}
	return result, nil
}

func (a *Application) RevokeDevice(ctx context.Context, principal httpapi.Principal, deviceID string) error {
	releaseAdmission := a.acquireTerminalAdmission(principal.OwnerID, deviceID)
	defer releaseAdmission()
	if err := a.deps.Sessions.RevokeDevice(ctx, principal.OwnerID, deviceID); err != nil {
		return err
	}
	disconnected := a.deps.Terminals.RevokeDevice(principal.OwnerID, deviceID)
	previewGrantsRevoked := 0
	if a.deps.PreviewTokens != nil {
		previewGrantsRevoked = a.deps.PreviewTokens.RevokeDevice(principal.OwnerID, deviceID)
	}
	a.audit(principal, "", "device.revoke", "success", "device", deviceID, map[string]any{
		"current": deviceID == principal.DeviceID, "terminal_connections_revoked": disconnected,
		"preview_grants_revoked": previewGrantsRevoked,
	})
	return nil
}

func registrationChallenge(start passkeys.RegistrationStart) (httpapi.PasskeyRegistrationChallenge, error) {
	if start.CeremonyID == "" || start.Options == nil {
		return httpapi.PasskeyRegistrationChallenge{}, errors.New("passkey service returned an incomplete registration challenge")
	}
	options := start.Options.Response
	userID, err := userIDString(options.User.ID)
	if err != nil {
		return httpapi.PasskeyRegistrationChallenge{}, err
	}
	excluded := make([]string, 0, len(options.CredentialExcludeList))
	for _, descriptor := range options.CredentialExcludeList {
		excluded = append(excluded, descriptor.CredentialID.String())
	}
	return httpapi.PasskeyRegistrationChallenge{
		CeremonyID:            start.CeremonyID,
		Challenge:             options.Challenge.String(),
		RelyingPartyID:        options.RelyingParty.ID,
		UserID:                userID,
		UserName:              options.User.Name,
		UserDisplayName:       options.User.DisplayName,
		ExcludedCredentialIDs: excluded,
	}, nil
}

func authenticationChallenge(start passkeys.LoginStart) (httpapi.PasskeyAuthenticationChallenge, error) {
	if start.CeremonyID == "" || start.Options == nil {
		return httpapi.PasskeyAuthenticationChallenge{}, errors.New("passkey service returned an incomplete authentication challenge")
	}
	options := start.Options.Response
	allowed := make([]string, 0, len(options.AllowedCredentials))
	for _, descriptor := range options.AllowedCredentials {
		allowed = append(allowed, descriptor.CredentialID.String())
	}
	return httpapi.PasskeyAuthenticationChallenge{
		CeremonyID:           start.CeremonyID,
		Challenge:            options.Challenge.String(),
		RelyingPartyID:       options.RelyingPartyID,
		AllowedCredentialIDs: allowed,
	}, nil
}

func userIDString(value any) (string, error) {
	switch typed := value.(type) {
	case protocol.URLEncodedBase64:
		return typed.String(), nil
	case []byte:
		return base64.RawURLEncoding.EncodeToString(typed), nil
	case string:
		if typed == "" {
			return "", errors.New("passkey user ID is empty")
		}
		return typed, nil
	default:
		return "", errors.New("passkey service returned an unsupported user ID")
	}
}

func registrationCredentialJSON(value httpapi.PasskeyRegistrationCredential) ([]byte, error) {
	if err := validateCredentialIdentity(value.CredentialID, value.RawID); err != nil {
		return nil, err
	}
	if _, err := decodeBase64URL("client data", value.ClientDataJSON, 1<<20); err != nil {
		return nil, err
	}
	if _, err := decodeBase64URL("attestation object", value.AttestationObject, 4<<20); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		} `json:"response"`
		ClientExtensionResults map[string]any `json:"clientExtensionResults"`
	}{
		ID:    value.CredentialID,
		RawID: value.RawID,
		Type:  "public-key",
		Response: struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		}{value.ClientDataJSON, value.AttestationObject},
		ClientExtensionResults: map[string]any{},
	})
}

func assertionCredentialJSON(value httpapi.PasskeyAssertionCredential) ([]byte, error) {
	if err := validateCredentialIdentity(value.CredentialID, value.RawID); err != nil {
		return nil, err
	}
	for _, item := range []struct {
		name  string
		value string
		limit int
	}{
		{"client data", value.ClientDataJSON, 1 << 20},
		{"authenticator data", value.AuthenticatorData, 1 << 20},
		{"signature", value.Signature, 1 << 20},
	} {
		if _, err := decodeBase64URL(item.name, item.value, item.limit); err != nil {
			return nil, err
		}
	}
	if value.UserHandle != nil {
		if _, err := decodeBase64URL("user handle", *value.UserHandle, 1024); err != nil {
			return nil, err
		}
	}
	return json.Marshal(struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			ClientDataJSON    string  `json:"clientDataJSON"`
			AuthenticatorData string  `json:"authenticatorData"`
			Signature         string  `json:"signature"`
			UserHandle        *string `json:"userHandle,omitempty"`
		} `json:"response"`
		ClientExtensionResults map[string]any `json:"clientExtensionResults"`
	}{
		ID:    value.CredentialID,
		RawID: value.RawID,
		Type:  "public-key",
		Response: struct {
			ClientDataJSON    string  `json:"clientDataJSON"`
			AuthenticatorData string  `json:"authenticatorData"`
			Signature         string  `json:"signature"`
			UserHandle        *string `json:"userHandle,omitempty"`
		}{value.ClientDataJSON, value.AuthenticatorData, value.Signature, value.UserHandle},
		ClientExtensionResults: map[string]any{},
	})
}

func validateCredentialIdentity(id, rawID string) error {
	decodedID, err := decodeBase64URL("credential ID", id, 1024)
	if err != nil {
		return err
	}
	decodedRaw, err := decodeBase64URL("raw credential ID", rawID, 1024)
	if err != nil {
		return err
	}
	if !bytes.Equal(decodedID, decodedRaw) {
		return errors.New("credential ID and raw ID do not match")
	}
	return nil
}

func decodeBase64URL(name, value string, maximum int) ([]byte, error) {
	if value == "" || len(value) > maximum*2 {
		return nil, fmt.Errorf("%s is empty or oversized", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s is not canonical base64url", name)
	}
	return decoded, nil
}

func sessionTokens(pair session.Pair, deviceID string) httpapi.SessionTokens {
	return httpapi.SessionTokens{
		AccessToken:      pair.AccessToken,
		AccessExpiresAt:  pair.AccessExpiresAt,
		RefreshToken:     pair.RefreshToken,
		RefreshExpiresAt: pair.RefreshExpiresAt,
		DeviceID:         deviceID,
	}
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
