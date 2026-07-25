package coder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/codex"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/coder/websocket"
)

type TerminalKind string

const (
	initialPromptSettleDelay = 750 * time.Millisecond
	ptyWriteTimeout          = 15 * time.Second
	ptyOutputChunkBytes      = terminal.RuntimeOutputChunkBytes
	ptyOutputQueueChunks     = terminal.RuntimeOutputQueueChunks
)

const (
	TerminalCodex  TerminalKind = "codex"
	TerminalShell  TerminalKind = "shell"
	TerminalServer TerminalKind = "server"
	TerminalTest   TerminalKind = "test"
	TerminalLog    TerminalKind = "log"
)

type PTYConfig struct {
	AgentID       string
	ReconnectID   string
	SessionName   string
	Kind          TerminalKind
	CodexTabID    string
	CodexThreadID string
	InitialPrompt string
	// InitialPromptDelivered is invoked once, after the prompt bytes have been
	// accepted by the live Coder PTY. It must be non-blocking and idempotent.
	InitialPromptDelivered func()
	InitialSize            terminal.Size
}

type PTYRuntime struct {
	client      *Client
	config      PTYConfig
	command     string
	ctx         context.Context
	cancel      context.CancelFunc
	output      chan []byte
	done        chan struct{}
	mu          sync.RWMutex
	writeGate   chan struct{}
	conn        *websocket.Conn
	size        terminal.Size
	closeOnce   sync.Once
	initialSent bool
	// initialPromptConnection is set only after the real child has emitted PTY
	// output. It prevents a prompt from being written into an unopened socket,
	// a device-login screen that has not rendered, or a replacement reconnect.
	initialPromptConnection *websocket.Conn
}

func (c *Client) OpenPTY(config PTYConfig) (*PTYRuntime, error) {
	if !safeIdentifier.MatchString(config.AgentID) || !uuidPattern.MatchString(config.ReconnectID) || !safeSessionName.MatchString(config.SessionName) {
		return nil, errors.New("invalid persistent PTY identity")
	}
	if config.InitialSize.Rows == 0 || config.InitialSize.Columns == 0 {
		config.InitialSize = terminal.Size{Rows: 24, Columns: 80}
	}
	if len(config.InitialPrompt) > 100000 || !utf8.ValidString(config.InitialPrompt) || strings.ContainsRune(config.InitialPrompt, '\x00') {
		return nil, errors.New("invalid Codex initial prompt")
	}
	command, err := tmuxCommand(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	writeGate := make(chan struct{}, 1)
	writeGate <- struct{}{}
	runtime := &PTYRuntime{client: c, config: config, command: command, ctx: ctx, cancel: cancel, output: make(chan []byte, ptyOutputQueueChunks), done: make(chan struct{}), writeGate: writeGate, size: config.InitialSize}
	go runtime.run()
	return runtime, nil
}

func (r *PTYRuntime) Output() <-chan []byte { return r.output }

func (r *PTYRuntime) WriteInput(ctx context.Context, input []byte) error {
	if len(input) > 64<<10 || !utf8.Valid(input) {
		return errors.New("invalid Coder PTY input")
	}
	return r.write(ctx, map[string]string{"data": string(input)})
}

func (r *PTYRuntime) Resize(ctx context.Context, size terminal.Size) error {
	if size.Rows == 0 || size.Columns == 0 {
		return errors.New("invalid Coder PTY size")
	}
	r.mu.Lock()
	r.size = size
	r.mu.Unlock()
	return r.write(ctx, map[string]uint16{"height": size.Rows, "width": size.Columns})
}

func (r *PTYRuntime) Close() error {
	r.closeOnce.Do(func() {
		r.cancel()
		r.mu.Lock()
		if r.conn != nil {
			_ = r.conn.Close(websocket.StatusNormalClosure, "runtime detached")
		}
		r.mu.Unlock()
		<-r.done
	})
	return nil
}

func (r *PTYRuntime) run() {
	defer close(r.done)
	defer close(r.output)
	delay := 100 * time.Millisecond
	for r.ctx.Err() == nil {
		r.mu.RLock()
		size := r.size
		r.mu.RUnlock()
		endpoint, header, err := r.client.ptyEndpoint(r.config.AgentID, r.config.ReconnectID, r.command, size.Columns, size.Rows)
		if err != nil {
			return
		}
		conn, _, err := websocket.Dial(r.ctx, endpoint, &websocket.DialOptions{HTTPHeader: header})
		if err != nil {
			if !r.wait(delay) {
				return
			}
			delay = min(delay*2, 5*time.Second)
			continue
		}
		conn.SetReadLimit(terminal.MaxPayload)
		r.mu.Lock()
		r.conn = conn
		r.mu.Unlock()
		delay = 100 * time.Millisecond
		for {
			messageType, data, readErr := conn.Read(r.ctx)
			if readErr != nil {
				break
			}
			if messageType != websocket.MessageBinary || len(data) > terminal.MaxPayload {
				_ = conn.Close(websocket.StatusUnsupportedData, "invalid Coder PTY output")
				break
			}
			r.scheduleInitialPrompt(conn, data)
			if err := enqueuePTYOutput(r.ctx, r.output, data); err != nil {
				_ = conn.CloseNow()
				return
			}
		}
		r.mu.Lock()
		if r.conn == conn {
			r.conn = nil
		}
		if r.initialPromptConnection == conn {
			r.initialPromptConnection = nil
		}
		r.mu.Unlock()
		_ = conn.CloseNow()
		if !r.wait(delay) {
			return
		}
		delay = min(delay*2, 5*time.Second)
	}
}

func enqueuePTYOutput(ctx context.Context, output chan<- []byte, data []byte) error {
	for len(data) > 0 {
		size := min(len(data), ptyOutputChunkBytes)
		chunk := append([]byte(nil), data[:size]...)
		select {
		case output <- chunk:
			data = data[size:]
		case <-ctx.Done():
			clear(chunk)
			return ctx.Err()
		}
	}
	return nil
}

// scheduleInitialPrompt establishes a content-agnostic readiness barrier: the
// trusted Codex child must emit output and keep the same PTY connection alive
// through a short settle interval. We deliberately do not scrape TUI text or
// ANSI sequences to infer readiness.
func (r *PTYRuntime) scheduleInitialPrompt(conn *websocket.Conn, output []byte) {
	if len(output) == 0 || r.config.Kind != TerminalCodex {
		return
	}
	r.mu.Lock()
	if r.initialSent || r.config.InitialPrompt == "" || r.initialPromptConnection != nil || r.conn != conn {
		r.mu.Unlock()
		return
	}
	r.initialPromptConnection = conn
	r.mu.Unlock()
	go func() {
		timer := time.NewTimer(initialPromptSettleDelay)
		defer timer.Stop()
		select {
		case <-r.ctx.Done():
			return
		case <-timer.C:
		}
		if err := r.sendInitialPrompt(conn); err != nil {
			r.mu.Lock()
			if r.initialPromptConnection == conn {
				r.initialPromptConnection = nil
			}
			r.mu.Unlock()
			_ = conn.CloseNow()
		}
	}()
}

func (r *PTYRuntime) sendInitialPrompt(conn *websocket.Conn) error {
	r.mu.RLock()
	prompt, sent := r.config.InitialPrompt, r.initialSent
	ready := r.conn == conn && r.initialPromptConnection == conn
	r.mu.RUnlock()
	if sent || prompt == "" || r.config.Kind != TerminalCodex {
		return nil
	}
	if !ready {
		return errors.New("Codex TUI readiness connection changed")
	}
	data, err := json.Marshal(map[string]string{"data": prompt + "\n"})
	if err != nil {
		return err
	}
	err = serializedPTYWrite(r.ctx, r.ctx, r.writeGate, ptyWriteTimeout, func(writeCtx context.Context) error {
		r.mu.RLock()
		stillReady := r.conn == conn && r.initialPromptConnection == conn && !r.initialSent
		r.mu.RUnlock()
		if !stillReady {
			return errors.New("Codex TUI readiness connection changed")
		}
		return conn.Write(writeCtx, websocket.MessageBinary, data)
	})
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.initialSent = true
	r.initialPromptConnection = nil
	r.config.InitialPrompt = ""
	delivered := r.config.InitialPromptDelivered
	r.config.InitialPromptDelivered = nil
	r.mu.Unlock()
	if delivered != nil {
		go func() {
			defer func() { _ = recover() }()
			delivered()
		}()
	}
	return nil
}

func (r *PTYRuntime) write(ctx context.Context, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return serializedPTYWrite(ctx, r.ctx, r.writeGate, ptyWriteTimeout, func(writeCtx context.Context) error {
		r.mu.RLock()
		conn := r.conn
		r.mu.RUnlock()
		if conn == nil {
			return errors.New("Coder PTY is reconnecting")
		}
		if err := conn.Write(writeCtx, websocket.MessageBinary, data); err != nil {
			return fmt.Errorf("write Coder PTY: %w", err)
		}
		return nil
	})
}

// serializedPTYWrite bounds the complete queue-and-write interval. Every
// holder of writeGate uses this helper, so a stalled transport cannot leave a
// revoked input queued forever. Cancellation is checked again immediately
// after acquiring the semaphore before the callback can mutate the PTY.
func serializedPTYWrite(ctx, runtimeCtx context.Context, writeGate chan struct{}, timeout time.Duration, write func(context.Context) error) error {
	if ctx == nil || runtimeCtx == nil || writeGate == nil || cap(writeGate) != 1 || write == nil || timeout <= 0 {
		return errors.New("invalid Coder PTY write boundary")
	}
	writeCtx, cancel := context.WithTimeout(ctx, timeout)
	stopRuntimeCancel := context.AfterFunc(runtimeCtx, cancel)
	defer func() {
		stopRuntimeCancel()
		cancel()
	}()

	select {
	case <-writeCtx.Done():
		return writeCtx.Err()
	case <-runtimeCtx.Done():
		return runtimeCtx.Err()
	case <-writeGate:
	}
	defer func() { writeGate <- struct{}{} }()
	if err := runtimeCtx.Err(); err != nil {
		return err
	}
	if err := writeCtx.Err(); err != nil {
		return err
	}
	return write(writeCtx)
}

func (r *PTYRuntime) wait(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-r.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func tmuxCommand(config PTYConfig) (string, error) {
	if !safeSessionName.MatchString(config.SessionName) {
		return "", errors.New("invalid tmux session name")
	}
	inner := "exec /opt/codex-mobile-helper/codex-mobile-workspace-helper terminal " + string(config.Kind)
	switch config.Kind {
	case TerminalCodex:
		if _, err := terminal.ParseTabID(config.CodexTabID); err != nil {
			return "", errors.New("invalid Codex terminal tab identity")
		}
		if _, err := codex.LaunchArgs(config.CodexThreadID); err != nil {
			return "", err
		}
		inner += " " + strings.ToLower(config.CodexTabID)
		if config.CodexThreadID != "" {
			inner += " " + config.CodexThreadID
		}
	case TerminalShell, TerminalServer, TerminalTest, TerminalLog:
	default:
		return "", errors.New("invalid terminal kind")
	}
	// Every variable component is validated to contain no shell metacharacters;
	// the remaining command is fixed by the control plane.
	return "tmux new-session -A -s " + config.SessionName + " -c /workspaces/repository \"" + inner + "\"", nil
}

var safeSessionName = regexp.MustCompile(`^cm-[a-z0-9][a-z0-9-]{0,47}$`)

var _ terminal.Runtime = (*PTYRuntime)(nil)
