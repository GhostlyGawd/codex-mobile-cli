package main

import (
	"errors"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/apns"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/codex"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/config"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/notifications"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
)

// configureNotifications owns the complete event delivery chain. It retains
// the APNs client in the dispatcher and always keeps the stable OSC 9 adapter
// as the terminal fallback; the experimental app-server flag must not disable
// this path.
func configureNotifications(cfg config.Config, state *postgres.ApplicationStore, terminals *terminal.Manager, recorder notifications.Recorder) (*notifications.Dispatcher, error) {
	if state == nil || terminals == nil {
		return nil, errors.New("notification state and terminal manager are required")
	}
	var sender notifications.Sender
	if cfg.APNSEnabled {
		productionKey, err := apns.ParsePrivateKey(cfg.APNSProductionPrivateKey)
		if err != nil {
			return nil, err
		}
		var sandboxKey apns.Key
		if len(cfg.APNSSandboxPrivateKey) != 0 || cfg.APNSSandboxKeyID != "" {
			if len(cfg.APNSSandboxPrivateKey) == 0 || cfg.APNSSandboxKeyID == "" {
				return nil, errors.New("sandbox APNs key ID and private key must be configured together")
			}
			key, err := apns.ParsePrivateKey(cfg.APNSSandboxPrivateKey)
			if err != nil {
				return nil, err
			}
			sandboxKey = apns.Key{ID: cfg.APNSSandboxKeyID, PrivateKey: key}
		}
		client, err := apns.New(apns.Config{
			TeamID: cfg.APNSTeamID, BundleID: cfg.IOSBundleID,
			ProductionKey: apns.Key{ID: cfg.APNSProductionKeyID, PrivateKey: productionKey},
			SandboxKey:    sandboxKey,
		})
		if err != nil {
			return nil, err
		}
		sender = client
	}
	dispatcher, err := notifications.New(notifications.Config{
		APNSEnabled: cfg.APNSEnabled, Topic: cfg.IOSBundleID, PublicOrigin: cfg.PublicOrigin,
		Recorder: recorder,
	}, state, terminals, sender)
	if err != nil {
		return nil, err
	}
	if err := terminals.ConfigureCodexEvents(func() codex.EventProvider { return &codex.OSC9Provider{} }, dispatcher); err != nil {
		_ = dispatcher.Close()
		return nil, err
	}
	return dispatcher, nil
}
