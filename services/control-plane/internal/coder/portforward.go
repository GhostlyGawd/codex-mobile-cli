package coder

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

const (
	maximumPortForwards       = 100
	portForwardStartupTimeout = 30 * time.Second
)

var errPortForwardStartupTimeout = errors.New("Coder port-forward did not become ready before the startup deadline")

type forwardKey struct {
	workspaceID string
	remotePort  uint16
}

type portForward struct {
	key        forwardKey
	localPort  uint16
	cancel     context.CancelFunc
	ready      chan struct{}
	done       chan struct{}
	readyError error
	readyOnce  sync.Once
}

type PortForwardManager struct {
	client *Client
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	items  map[forwardKey]*portForward

	startupTimeout  time.Duration
	maximumForwards int
}

func NewPortForwardManager(client *Client) (*PortForwardManager, error) {
	if client == nil {
		return nil, errors.New("Coder client is required for port forwarding")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &PortForwardManager{
		client: client, ctx: ctx, cancel: cancel, items: make(map[forwardKey]*portForward),
		startupTimeout: portForwardStartupTimeout, maximumForwards: maximumPortForwards,
	}, nil
}

// Target returns a private loopback HTTP target backed by the pinned Coder
// CLI's raw TCP tunnel. The Coder credential remains in the trusted CLI child
// process and is never forwarded as an HTTP header to workspace code.
func (m *PortForwardManager) Target(ctx context.Context, workspaceID string, remotePort uint16) (*url.URL, error) {
	if ctx == nil || !uuidPattern.MatchString(workspaceID) || remotePort < 1024 {
		return nil, errors.New("invalid Coder port-forward target")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := forwardKey{workspaceID: workspaceID, remotePort: remotePort}
	m.mu.Lock()
	// Check while holding the same lock used by Revoke. If route revocation
	// canceled the request before the forward existed, this prevents a late
	// gateway Target call from recreating a tunnel after Revoke found nothing.
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	item := m.items[key]
	if item == nil {
		maximumForwards := m.maximumForwards
		if maximumForwards <= 0 {
			maximumForwards = maximumPortForwards
		}
		if len(m.items) >= maximumForwards {
			m.mu.Unlock()
			return nil, errors.New("Coder port-forward limit reached")
		}
		var err error
		item, err = m.startLocked(key)
		if err != nil {
			m.mu.Unlock()
			return nil, err
		}
		m.items[key] = item
	}
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-item.ready:
		if item.readyError != nil {
			// Startup failures, including the internal deadline, do not return
			// until the local CLI process is canceled and reaped. This makes the
			// capacity slot reusable before the caller can retry.
			<-item.done
			return nil, item.readyError
		}
		return url.Parse("http://127.0.0.1:" + strconv.Itoa(int(item.localPort)))
	}
}

func (m *PortForwardManager) Revoke(workspaceID string, remotePort uint16) {
	key := forwardKey{workspaceID: workspaceID, remotePort: remotePort}
	m.mu.Lock()
	item := m.items[key]
	delete(m.items, key)
	m.mu.Unlock()
	if item != nil {
		item.cancel()
		<-item.done
	}
}

func (m *PortForwardManager) Close() error {
	m.cancel()
	m.mu.Lock()
	items := make([]*portForward, 0, len(m.items))
	for key, item := range m.items {
		items = append(items, item)
		delete(m.items, key)
	}
	m.mu.Unlock()
	for _, item := range items {
		item.cancel()
	}
	for _, item := range items {
		<-item.done
	}
	return nil
}

func (m *PortForwardManager) startLocked(key forwardKey) (*portForward, error) {
	localPort, err := reserveLoopbackPort()
	if err != nil {
		return nil, err
	}
	processContext, cancel := context.WithCancel(m.ctx)
	item := &portForward{key: key, localPort: localPort, cancel: cancel, ready: make(chan struct{}), done: make(chan struct{})}
	args := portForwardArguments(key.workspaceID, localPort, key.remotePort)
	commandContext := m.client.commandContext
	if commandContext == nil {
		commandContext = exec.CommandContext
	}
	cmd := commandContext(processContext, m.client.cliPath, args...)
	cmd.Dir = trustedHelperWorkingDirectory
	cmd.Env = helperEnvironment(m.client.base.String(), m.client.token)
	cmd.WaitDelay = helperProcessWaitDelay
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, errors.New("open Coder port-forward output")
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, errors.New("open Coder port-forward diagnostics")
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start Coder port-forward: %w", err)
	}
	go func() { _, _ = io.Copy(io.Discard, io.LimitReader(stdout, 1<<20)) }()
	go func() {
		scanner := bufio.NewScanner(io.LimitReader(stderr, 1<<20))
		for scanner.Scan() {
			if scanner.Text() == "Ready!" {
				item.markReady(nil)
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		item.markReady(errors.New("Coder port-forward exited before becoming ready"))
		_ = err // Raw CLI diagnostics are intentionally not surfaced.
		close(item.done)
		m.mu.Lock()
		if m.items[key] == item {
			delete(m.items, key)
		}
		m.mu.Unlock()
	}()
	go m.enforceStartupDeadline(item)
	return item, nil
}

func (m *PortForwardManager) enforceStartupDeadline(item *portForward) {
	startupTimeout := m.startupTimeout
	if startupTimeout <= 0 {
		startupTimeout = portForwardStartupTimeout
	}
	timer := time.NewTimer(startupTimeout)
	defer timer.Stop()
	select {
	case <-item.ready:
		return
	case <-timer.C:
	}
	if !item.markReady(errPortForwardStartupTimeout) {
		return
	}
	m.mu.Lock()
	if m.items[item.key] == item {
		delete(m.items, item.key)
	}
	m.mu.Unlock()
	item.cancel()
	<-item.done
}

func (f *portForward) markReady(err error) bool {
	marked := false
	f.readyOnce.Do(func() {
		f.readyError = err
		close(f.ready)
		marked = true
	})
	return marked
}

func reserveLoopbackPort() (uint16, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, errors.New("reserve private preview port")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil || port <= 0 || port > 65535 {
		return 0, errors.New("release private preview port reservation")
	}
	return uint16(port), nil
}

func portForwardArguments(workspaceID string, localPort, remotePort uint16) []string {
	specification := "127.0.0.1:" + strconv.Itoa(int(localPort)) + ":" + strconv.Itoa(int(remotePort))
	return []string{"port-forward", "--disable-autostart", workspaceID, "--tcp", specification}
}
