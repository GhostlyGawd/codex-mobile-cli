package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/config"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
)

const rewrapMasterKeyConfirmation = "--confirm=REWRAP-ALL-ENVELOPES"

func rewrapMasterKey(ctx context.Context, cfg config.Config, args []string, logger *slog.Logger) error {
	if len(args) != 2 || args[1] != rewrapMasterKeyConfirmation {
		return errors.New("rewrap-master-key requires NEW_KEY_FILE --confirm=REWRAP-ALL-ENVELOPES")
	}
	newMaster, err := readNewMasterKeyFile(args[0])
	if err != nil {
		return err
	}
	defer clear(newMaster)
	defer clear(cfg.MasterKey)
	if len(cfg.MasterKey) != 32 {
		return errors.New("the configured current master key is invalid")
	}
	if subtle.ConstantTimeCompare(cfg.MasterKey, newMaster) == 1 {
		return errors.New("the new master key must differ from the current master key")
	}
	current, err := vault.New(cfg.MasterKey)
	if err != nil {
		return errors.New("initialize the current master-key vault")
	}
	defer current.Destroy()
	startup, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := openDatabase(startup, cfg, "codex-mobile-master-key-rewrap")
	if err != nil {
		return err
	}
	defer pool.Close()
	rotator, err := postgres.NewMasterKeyRotator(pool, current)
	if err != nil {
		return err
	}
	summary, err := rotator.Rotate(startup, newMaster, time.Now().UTC())
	if err != nil {
		return err
	}
	logger.Info("master-key envelopes rewrapped",
		"passkeys", summary.Passkeys,
		"encrypted_secrets", summary.EncryptedSecrets,
		"apns_tokens", summary.APNSTokens,
		"total", summary.Total(),
	)
	return nil
}

func readNewMasterKeyFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" || len(path) > 4096 || strings.ContainsRune(path, '\x00') {
		return nil, errors.New("new master key file path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("read new master key file metadata")
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4096 {
		return nil, errors.New("new master key file must be a bounded regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("new master key file permissions must not grant group or other access")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read new master key file")
	}
	defer clear(content)
	if len(content) == 32 {
		return bytes.Clone(content), nil
	}
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 32 {
		return bytes.Clone(trimmed), nil
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	decodedBytes, err := base64.StdEncoding.Decode(decoded, trimmed)
	if err != nil || decodedBytes != 32 {
		clear(decoded)
		return nil, errors.New("new master key file must contain exactly 32 raw bytes or their base64 encoding")
	}
	return decoded[:decodedBytes], nil
}
