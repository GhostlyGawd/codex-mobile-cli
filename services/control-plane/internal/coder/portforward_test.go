package coder

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestPortForwardArgumentsAreLoopbackOnlyAndFixed(t *testing.T) {
	t.Parallel()
	workspaceID := "123e4567-e89b-12d3-a456-426614174000"
	got := portForwardArguments(workspaceID, 41000, 3000)
	want := []string{"port-forward", "--disable-autostart", workspaceID, "--tcp", "127.0.0.1:41000:3000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("port-forward args = %#v, want %#v", got, want)
	}
}

func TestReserveLoopbackPort(t *testing.T) {
	port, err := reserveLoopbackPort()
	if err != nil || port == 0 {
		t.Fatalf("reserve loopback port = %d, %v", port, err)
	}
}

func TestPortForwardRevokeCancelsAndReleasesCapacity(t *testing.T) {
	t.Parallel()
	processContext, cancel := context.WithCancel(context.Background())
	key := forwardKey{workspaceID: "123e4567-e89b-12d3-a456-426614174000", remotePort: 3000}
	item := &portForward{
		key:    key,
		cancel: cancel,
		ready:  make(chan struct{}),
		done:   make(chan struct{}),
	}
	manager := &PortForwardManager{items: map[forwardKey]*portForward{key: item}}
	go func() {
		<-processContext.Done()
		close(item.done)
	}()

	manager.Revoke(key.workspaceID, key.remotePort)
	select {
	case <-processContext.Done():
	case <-time.After(time.Second):
		t.Fatal("revoked port-forward process was not canceled")
	}
	manager.mu.Lock()
	remaining := len(manager.items)
	_, retained := manager.items[key]
	manager.mu.Unlock()
	if retained || remaining != 0 {
		t.Fatalf("revoked port-forward retained in capacity map: retained=%t count=%d", retained, remaining)
	}
}

func TestPortForwardTargetDoesNotCreateTunnelForRevokedRequest(t *testing.T) {
	t.Parallel()
	requestContext, cancel := context.WithCancel(context.Background())
	cancel()
	manager := &PortForwardManager{
		ctx:   context.Background(),
		items: make(map[forwardKey]*portForward),
	}
	if _, err := manager.Target(requestContext, "123e4567-e89b-12d3-a456-426614174000", 3000); err != context.Canceled {
		t.Fatalf("Target error = %v, want context canceled", err)
	}
	manager.mu.Lock()
	created := len(manager.items)
	manager.mu.Unlock()
	if created != 0 {
		t.Fatalf("canceled request created %d port-forward entries", created)
	}
}

func TestPortForwardStartupDeadlineReapsProcessAndRestoresCapacity(t *testing.T) {
	client, err := New(Config{
		URL: "https://coder.example.test", Token: "port-forward-child-token",
		OrganizationID: "org", OwnerID: "me", TemplateID: "template",
	})
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]*exec.Cmd, 0, 2)
	client.commandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		child := "TestPortForwardReadyChild"
		if len(commands) == 0 {
			child = "TestPortForwardBlockingChild"
		}
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+child+"$")
		commands = append(commands, command)
		return command
	}
	manager, err := NewPortForwardManager(client)
	if err != nil {
		t.Fatal(err)
	}
	manager.startupTimeout = 200 * time.Millisecond
	manager.maximumForwards = 1
	defer func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	}()
	workspaceID := "123e4567-e89b-12d3-a456-426614174000"

	if _, err := manager.Target(context.Background(), workspaceID, 3000); !errors.Is(err, errPortForwardStartupTimeout) {
		t.Fatalf("hung port-forward startup = %v", err)
	}
	manager.mu.Lock()
	remaining := len(manager.items)
	manager.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("timed-out port-forward retained %d capacity entries", remaining)
	}

	target, err := manager.Target(context.Background(), workspaceID, 3001)
	if err != nil {
		t.Fatalf("capacity was not reusable after timeout: %v", err)
	}
	if target.Scheme != "http" || target.Hostname() != "127.0.0.1" {
		t.Fatalf("replacement port-forward target = %v", target)
	}
	if len(commands) != 2 {
		t.Fatalf("port-forward command count = %d, want 2", len(commands))
	}
	for index, command := range commands {
		if command.Dir != trustedHelperWorkingDirectory {
			t.Fatalf("port-forward command %d directory = %q, want %q", index, command.Dir, trustedHelperWorkingDirectory)
		}
	}
}

func TestPortForwardBlockingChild(t *testing.T) {
	if os.Getenv("CODER_SESSION_TOKEN") != "port-forward-child-token" {
		return
	}
	time.Sleep(10 * time.Minute)
}

func TestPortForwardReadyChild(t *testing.T) {
	if os.Getenv("CODER_SESSION_TOKEN") != "port-forward-child-token" {
		return
	}
	_, _ = fmt.Fprintln(os.Stderr, "Ready!")
	time.Sleep(10 * time.Minute)
}
