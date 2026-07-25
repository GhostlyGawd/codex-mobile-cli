//go:build !linux

package workspacehelper

func requireMemoryBackedTemporaryRoot(string) error { return nil }
