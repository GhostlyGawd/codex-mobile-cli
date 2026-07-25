package workspacehelper

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/gitops"
	secretmodel "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/secrets"
)

const maximumRuntimeSecretsFileBytes = 128 << 10

func runtimeSecretsPath(temporaryRoot string) string {
	return filepath.Join(temporaryRoot, "codex-mobile-runtime", "secrets.json")
}

func validateRuntimeSecrets(values map[string][]byte) error {
	if len(values) > secretmodel.MaximumGrantsPerWorkspace {
		return errors.New("invalid granted runtime secrets")
	}
	total := 0
	for name, value := range values {
		if !secretmodel.ValidName(name) || reservedEnvironmentName(name) || secretmodel.ValidateValue(value) != nil {
			return errors.New("invalid granted runtime secrets")
		}
		total += len(value)
		if total > secretmodel.MaximumGrantedBytes {
			return errors.New("invalid granted runtime secrets")
		}
	}
	return nil
}

func writeRuntimeSecrets(temporaryRoot string, values map[string][]byte) error {
	if temporaryRoot == "" || validateRuntimeSecrets(values) != nil {
		return errors.New("invalid granted runtime secrets")
	}
	if values == nil {
		values = map[string][]byte{}
	}
	path := runtimeSecretsPath(temporaryRoot)
	// Remove the previous grant set before installing the new one. If the new
	// bounded write fails, no stale or revoked values remain materialized.
	if err := secureRemove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("replace granted runtime secrets")
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return errors.New("encode granted runtime secrets")
	}
	defer wipeBytes(encoded)
	if len(encoded) > maximumRuntimeSecretsFileBytes {
		return errors.New("encode granted runtime secrets")
	}
	if err := atomicPrivateFile(path, encoded); err != nil {
		return errors.New("materialize granted runtime secrets")
	}
	return nil
}

func loadRuntimeSecrets(temporaryRoot string) (map[string][]byte, error) {
	if temporaryRoot == "" {
		return nil, errors.New("granted runtime secrets are unavailable")
	}
	content, err := readPrivateFile(runtimeSecretsPath(temporaryRoot), maximumRuntimeSecretsFileBytes)
	if err != nil {
		return nil, errors.New("granted runtime secrets are unavailable")
	}
	defer wipeBytes(content)
	decoder := json.NewDecoder(bytes.NewReader(content))
	var values map[string][]byte
	if err := decoder.Decode(&values); err != nil || values == nil {
		wipeRuntimeSecrets(values)
		return nil, errors.New("granted runtime secrets are invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) || validateRuntimeSecrets(values) != nil {
		wipeRuntimeSecrets(values)
		return nil, errors.New("granted runtime secrets are invalid")
	}
	return values, nil
}

func wipeRuntimeSecrets(values map[string][]byte) {
	for name, value := range values {
		wipeBytes(value)
		delete(values, name)
	}
}

func (h *Helper) purgeRuntimeSecrets() error {
	err := secureRemove(runtimeSecretsPath(h.temporaryRoot))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (h *Helper) runtimeSecretScanner(authoritative map[string][]byte) (*gitops.ValueSecretScanner, error) {
	if validateRuntimeSecrets(authoritative) != nil {
		return nil, errors.New("granted runtime secrets are invalid")
	}
	materialized, err := loadRuntimeSecrets(h.temporaryRoot)
	if err != nil {
		return nil, err
	}
	defer wipeRuntimeSecrets(materialized)
	if !sameRuntimeSecrets(materialized, authoritative) {
		return nil, errors.New("granted runtime secrets are stale")
	}
	items := make([][]byte, 0, len(authoritative))
	for _, value := range authoritative {
		items = append(items, value)
	}
	return gitops.NewValueSecretScanner(items...)
}

func sameRuntimeSecrets(materialized, authoritative map[string][]byte) bool {
	if len(materialized) != len(authoritative) {
		return false
	}
	for name, expected := range authoritative {
		actual, ok := materialized[name]
		if !ok || len(actual) != len(expected) || subtle.ConstantTimeCompare(actual, expected) != 1 {
			return false
		}
	}
	return true
}
