package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/admission"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/application"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/attachmentjanitor"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/checkpoint"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/coder"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/config"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubsync"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubworkspace"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/hostdisk"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/lifecycle"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/maintenance"
	controlmetrics "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/metrics"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/notifications"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/passkeys"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/preview"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/setupreview"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspace"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	startupTimeout  = 2 * time.Minute
	shutdownTimeout = 30 * time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(context.Background(), os.Args[1:], logger); err != nil {
		logger.Error("control plane stopped", "error", safeError(err))
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logger *slog.Logger) error {
	if logger == nil {
		return errors.New("logger is required")
	}
	command := "serve"
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}
	if command == "help" || command == "-h" || command == "--help" {
		_, _ = fmt.Fprintln(os.Stdout, "usage: control-plane [serve|migrate|bootstrap-token|recover-passkeys --confirm=REVOKE-ALL-PASSKEYS|rewrap-master-key NEW_KEY_FILE --confirm=REWRAP-ALL-ENVELOPES|github-sync INSTALLATION_ID]")
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	switch command {
	case "serve":
		if len(args) != 0 {
			return errors.New("serve accepts no arguments")
		}
		return serve(ctx, cfg, logger)
	case "migrate":
		if len(args) != 0 {
			return errors.New("migrate accepts no arguments")
		}
		return migrate(ctx, cfg, logger)
	case "bootstrap-token":
		if len(args) != 0 {
			return errors.New("bootstrap-token accepts no arguments")
		}
		return bootstrapToken(ctx, cfg)
	case "recover-passkeys":
		if len(args) != 1 || args[0] != "--confirm=REVOKE-ALL-PASSKEYS" {
			return errors.New("recover-passkeys requires --confirm=REVOKE-ALL-PASSKEYS and revokes every passkey, device, session, APNs endpoint, and preview token")
		}
		return recoverPasskeys(ctx, cfg)
	case "rewrap-master-key":
		return rewrapMasterKey(ctx, cfg, args, logger)
	case "github-sync":
		if len(args) != 1 {
			return errors.New("github-sync requires exactly one installation ID")
		}
		installationID, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil || installationID <= 0 {
			return errors.New("GitHub installation ID must be a positive integer")
		}
		return syncGitHub(ctx, cfg, installationID, logger)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func openDatabase(ctx context.Context, cfg config.Config, applicationName string) (*pgxpool.Pool, error) {
	if cfg.DatabaseURL == "" {
		return nil, errors.New("database configuration is required")
	}
	return postgres.Open(ctx, postgres.PoolConfig{
		URL: cfg.DatabaseURL, ApplicationName: applicationName,
		MaxConns: 16, MinConns: 2,
	})
}

func migrate(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	startup, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := openDatabase(startup, cfg, "codex-mobile-migrate")
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := migrations.Apply(startup, pool); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	logger.Info("database migrations are current")
	return nil
}

func bootstrapToken(ctx context.Context, cfg config.Config) error {
	startup, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := openDatabase(startup, cfg, "codex-mobile-bootstrap")
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := migrations.Apply(startup, pool); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	owner, err := singleOwnerID(startup, pool)
	if err == nil && owner != "" {
		return errors.New("an owner is already enrolled; bootstrap will not be re-enabled automatically")
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	store, err := postgres.NewBootstrapStore(pool)
	if err != nil {
		return err
	}
	manager, err := passkeys.NewBootstrapManagerWithStore(cfg.SessionPepper, cfg.BootstrapTTL, store)
	if err != nil {
		return err
	}
	token, expiresAt, err := manager.GenerateContext(startup)
	if err != nil {
		return fmt.Errorf("generate bootstrap token: %w", err)
	}
	// This command is the only intended plaintext disclosure. The token is
	// stored only as a keyed hash and expires quickly.
	_, err = fmt.Fprintf(os.Stdout, "Bootstrap token: %s\nExpires at: %s\n", token, expiresAt.Format(time.RFC3339))
	return err
}

func syncGitHub(ctx context.Context, cfg config.Config, installationID int64, logger *slog.Logger) error {
	if !cfg.GitHubEnabled {
		return errors.New("GitHub integration is disabled")
	}
	startup, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := openDatabase(startup, cfg, "codex-mobile-github-sync")
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := migrations.Apply(startup, pool); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	ownerID, err := singleOwnerID(startup, pool)
	if err != nil {
		return fmt.Errorf("resolve enrolled owner: %w", err)
	}
	client, err := githubapp.New(cfg.GitHubAppID, cfg.GitHubPrivateKey, nil)
	if err != nil {
		return err
	}
	repositories, err := postgres.NewRepositoryStore(pool)
	if err != nil {
		return err
	}
	syncer, err := githubsync.New(client, repositories)
	if err != nil {
		return err
	}
	// This explicit owner-run command is the only path that clears a local
	// disconnect. The reconnect and full synchronization share one exclusive
	// lease, and authority remains disabled unless synchronization succeeds.
	count, err := syncer.SyncOwnerReconnect(startup, ownerID, installationID)
	if err != nil {
		return fmt.Errorf("synchronize GitHub installation: %w", err)
	}
	logger.Info("GitHub installation synchronized", "installation_id", installationID, "repository_count", count)
	return nil
}

type serverRuntime struct {
	pool          *pgxpool.Pool
	serveLease    *postgres.ServeLease
	terminals     *terminal.Manager
	portForwards  *coder.PortForwardManager
	notifications *notifications.Dispatcher
	checkpoints   *checkpoint.Scheduler
	lifecycle     *lifecycle.Coordinator
	attachments   *attachmentjanitor.Janitor
	maintenance   *maintenance.Coordinator
	metrics       *controlmetrics.Registry
	handler       http.Handler
}

func (r *serverRuntime) Close() error {
	var result error
	if r.terminals != nil {
		result = errors.Join(result, r.terminals.Close())
	}
	if r.notifications != nil {
		result = errors.Join(result, r.notifications.Close())
	}
	if r.portForwards != nil {
		result = errors.Join(result, r.portForwards.Close())
	}
	if r.serveLease != nil {
		result = errors.Join(result, r.serveLease.Close())
	}
	if r.pool != nil {
		r.pool.Close()
	}
	return result
}

func serve(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	startup, cancelStartup := context.WithTimeout(ctx, startupTimeout)
	runtime, err := buildServer(startup, cfg)
	cancelStartup()
	if err != nil {
		return err
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			logger.Error("runtime cleanup failed", "error", safeError(err))
		}
	}()

	root, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if runtime.checkpoints != nil {
		checkpointCtx, cancelCheckpoints := context.WithCancel(root)
		checkpointDone := make(chan struct{})
		go func() {
			defer close(checkpointDone)
			runtime.checkpoints.Run(checkpointCtx, func(err error) {
				logger.Error("periodic workspace checkpoint failed", "error", safeError(err))
			})
		}()
		defer func() {
			cancelCheckpoints()
			<-checkpointDone
		}()
	}
	if runtime.lifecycle != nil {
		lifecycleCtx, cancelLifecycle := context.WithCancel(root)
		lifecycleDone := make(chan struct{})
		go func() {
			defer close(lifecycleDone)
			_ = runtime.lifecycle.Run(lifecycleCtx, func(err error) {
				logger.Error("workspace lifecycle scan failed", "error", safeError(err))
			})
		}()
		defer func() {
			cancelLifecycle()
			<-lifecycleDone
		}()
	}
	if runtime.attachments != nil {
		attachmentCtx, cancelAttachments := context.WithCancel(root)
		attachmentDone := make(chan struct{})
		go func() {
			defer close(attachmentDone)
			runtime.attachments.Run(attachmentCtx, func(err error) {
				logger.Error("workspace attachment cleanup failed", "error", safeError(err))
			})
		}()
		defer func() {
			cancelAttachments()
			<-attachmentDone
		}()
	}
	if runtime.maintenance != nil {
		maintenanceCtx, cancelMaintenance := context.WithCancel(root)
		maintenanceDone := make(chan struct{})
		go func() {
			defer close(maintenanceDone)
			runMaintenanceScheduler(maintenanceCtx, runtime.maintenance, runtime.pool, cfg.MaintenanceScanInterval, func(err error) {
				logger.Error("maintenance coordination failed", "error", safeError(err))
			})
		}()
		defer func() {
			cancelMaintenance()
			<-maintenanceDone
		}()
	}
	server := &http.Server{
		Addr: cfg.HTTPAddr, Handler: runtime.handler,
		// Body size/context limits live in the REST handlers. A server-wide
		// ReadTimeout would also become the inherited deadline of a hijacked,
		// long-lived terminal WebSocket.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute, MaxHeaderBytes: 32 << 10,
		BaseContext: func(net.Listener) context.Context { return root },
	}
	defer server.Close()
	metricsServer := &http.Server{
		Addr: cfg.MetricsAddr, Handler: runtime.metrics.Handler(),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
		BaseContext: func(net.Listener) context.Context { return root },
	}
	metricsListener, err := net.Listen("tcp", cfg.MetricsAddr)
	if err != nil {
		return fmt.Errorf("listen on private metrics address: %w", err)
	}
	defer metricsListener.Close()
	defer metricsServer.Close()
	metricsErrCh := make(chan error, 1)
	go func() { metricsErrCh <- metricsServer.Serve(metricsListener) }()
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	logger.Info("control plane listening", "address", cfg.HTTPAddr, "environment", cfg.Environment)
	logger.Info("private metrics listening", "address", cfg.MetricsAddr)
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	case err := <-metricsErrCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve private metrics: %w", err)
		}
		return nil
	case <-root.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		if err := metricsServer.Shutdown(shutdown); err != nil {
			_ = metricsServer.Close()
			return fmt.Errorf("graceful metrics shutdown: %w", err)
		}
		if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		if err := <-metricsErrCh; !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve private metrics: %w", err)
		}
		return nil
	}
}

func buildServer(ctx context.Context, cfg config.Config) (*serverRuntime, error) {
	pool, err := openDatabase(ctx, cfg, "codex-mobile-control-plane")
	if err != nil {
		return nil, err
	}
	var serveLease *postgres.ServeLease
	fail := func(cause error) (*serverRuntime, error) {
		if serveLease != nil {
			_ = serveLease.Close()
		}
		pool.Close()
		return nil, cause
	}
	serveLease, err = postgres.AcquireServeLease(ctx, pool)
	if err != nil {
		return fail(err)
	}
	if err := migrations.Apply(ctx, pool); err != nil {
		return fail(fmt.Errorf("apply migrations: %w", err))
	}
	cipher, err := vault.New(cfg.MasterKey)
	if err != nil {
		return fail(err)
	}
	bootstrapStore, err := postgres.NewBootstrapStore(pool)
	if err != nil {
		return fail(err)
	}
	bootstrap, err := passkeys.NewBootstrapManagerWithStore(cfg.SessionPepper, cfg.BootstrapTTL, bootstrapStore)
	if err != nil {
		return fail(err)
	}
	passkeyStore, err := postgres.NewPasskeyStore(pool, cipher)
	if err != nil {
		return fail(err)
	}
	passkeyService, err := passkeys.NewService(cfg.PasskeyRPID, "Codex Mobile", cfg.PasskeyOrigins, passkeyStore, bootstrap)
	if err != nil {
		return fail(err)
	}
	sessionStore, err := postgres.NewSessionStore(pool)
	if err != nil {
		return fail(err)
	}
	sessions, err := session.New(sessionStore, cfg.SessionPepper, cfg.AccessTTL, cfg.RefreshTTL)
	if err != nil {
		return fail(err)
	}
	repositories, err := postgres.NewRepositoryStore(pool)
	if err != nil {
		return fail(err)
	}
	state, err := postgres.NewApplicationStore(pool, cipher)
	if err != nil {
		return fail(err)
	}
	workspaceStore, err := postgres.NewWorkspaceStore(pool, func(context.Context) (int64, error) {
		return hostdisk.FreeGiB(cfg.WorkspaceDiskProbePath)
	})
	if err != nil {
		return fail(err)
	}
	coderClient, err := coder.New(coder.Config{
		URL: cfg.CoderURL, Token: cfg.CoderToken,
		OrganizationID: cfg.CoderOrganizationID, OwnerID: cfg.CoderOwnerID,
		TemplateID: cfg.CoderTemplateID, CLIPath: "coder",
	})
	if err != nil {
		return fail(err)
	}
	checkpointService, err := checkpoint.New(checkpoint.Config{
		Root: cfg.CheckpointRoot, Retention: cfg.CheckpointRetention,
		MaxWorkspaceBytes: cfg.CheckpointMaxBytes, MaxCheckpoints: cfg.CheckpointMaxCount,
	}, coderClient)
	if err != nil {
		return fail(err)
	}
	coderRuntime, err := application.NewCoderAdapter(coderClient)
	if err != nil {
		return fail(err)
	}
	capacity := admission.ReferenceCapacity()
	capacity.MaxRunning = cfg.MaxRunning
	controller, err := admission.New(capacity)
	if err != nil {
		return fail(err)
	}
	metricsRegistry := controlmetrics.New()

	var githubClient *githubapp.Client
	var detector workspace.EnvironmentDetector = unavailableEnvironmentDetector{}
	var initializer workspace.Initializer
	var webhook http.Handler
	if cfg.GitHubEnabled {
		githubClient, err = githubapp.New(cfg.GitHubAppID, cfg.GitHubPrivateKey, nil)
		if err != nil {
			return fail(err)
		}
		detector, err = githubworkspace.NewDetector(githubClient, repositories)
		if err != nil {
			return fail(err)
		}
		initializer, err = githubworkspace.NewInitializer(githubClient, coderClient, state, repositories)
		if err != nil {
			return fail(err)
		}
		syncer, err := githubsync.New(githubClient, repositories)
		if err != nil {
			return fail(err)
		}
		webhook, err = githubsync.NewWebhook([]byte(cfg.GitHubWebhookSecret), syncer, func(ctx context.Context) (string, error) {
			return singleOwnerID(ctx, pool)
		})
		if err != nil {
			return fail(err)
		}
	}

	var workspaceService *workspace.Service
	if initializer == nil {
		workspaceService, err = workspace.New(workspaceStore, repositories, detector, coderClient, controller, checkpointService)
	} else {
		workspaceService, err = workspace.New(workspaceStore, repositories, detector, coderClient, controller, checkpointService, initializer)
	}
	if err != nil {
		return fail(err)
	}
	runtimeProber, err := lifecycle.NewHelperProber(coderClient)
	if err != nil {
		return fail(err)
	}
	checkpointScheduler, err := checkpoint.NewScheduler(checkpointService, func(ctx context.Context) ([]core.Workspace, error) {
		ownerID, err := singleOwnerID(ctx, pool)
		if errors.Is(err, pgx.ErrNoRows) {
			return []core.Workspace{}, nil
		}
		if err != nil {
			return nil, err
		}
		return workspaceStore.List(ctx, ownerID)
	}, workspaceStore, cfg.CheckpointInterval, metricsRegistry)
	if err != nil {
		return fail(err)
	}
	attachmentJanitor, err := attachmentjanitor.New(coderClient, func(ctx context.Context) ([]core.Workspace, error) {
		ownerID, err := singleOwnerID(ctx, pool)
		if errors.Is(err, pgx.ErrNoRows) {
			return []core.Workspace{}, nil
		}
		if err != nil {
			return nil, err
		}
		return workspaceStore.List(ctx, ownerID)
	}, attachmentjanitor.DefaultInterval)
	if err != nil {
		return fail(err)
	}
	terminalManager, err := terminal.NewManager(cfg.SessionPepper, func(event terminal.AuditEvent) {
		details, _ := json.Marshal(map[string]string{"displaced_device_id": event.DisplacedDeviceID})
		auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = state.Audit(auditCtx, event.OwnerID, event.DeviceID, event.WorkspaceID, event.Kind, "success", "terminal_tab", event.TabID, details, time.Now().UTC())
	})
	if err != nil {
		return fail(err)
	}
	notificationDispatcher, err := configureNotifications(cfg, state, terminalManager, metricsRegistry)
	if err != nil {
		_ = terminalManager.Close()
		return fail(err)
	}
	failRuntime := func(cause error) (*serverRuntime, error) {
		_ = terminalManager.Close()
		_ = notificationDispatcher.Close()
		if serveLease != nil {
			_ = serveLease.Close()
		}
		pool.Close()
		return nil, cause
	}
	setupReviews, err := setupreview.New(state, notificationDispatcher, nil)
	if err != nil {
		return failRuntime(err)
	}
	lifecycleCoordinator, err := lifecycle.New(workspaceStore, state, workspaceService, runtimeProber, state, setupReviews, lifecycle.Config{
		ScanInterval: cfg.LifecycleScanInterval,
		WarningLead:  cfg.LifecycleWarningLead,
	})
	if err != nil {
		return failRuntime(err)
	}
	if err := terminalManager.ConfigureActivityObserver(func(event terminal.ActivityEvent) {
		lifecycleCoordinator.RecordActivity(lifecycle.ActivityEvent{
			OwnerID: event.OwnerID, WorkspaceID: event.WorkspaceID, At: event.At,
		})
	}); err != nil {
		return failRuntime(err)
	}
	terminalGateway, err := terminal.NewGateway(terminalManager, cfg.PublicOrigin)
	if err != nil {
		return failRuntime(err)
	}
	terminalURL, err := websocketURL(cfg.PublicOrigin)
	if err != nil {
		return failRuntime(err)
	}

	var previewTokens *preview.TokenManager
	var previewGateway http.Handler
	var portForwards *coder.PortForwardManager
	previewsConfigured := strings.TrimSpace(cfg.PreviewDomain) != ""
	if previewsConfigured {
		previewTokens, err = preview.NewTokenManager(cfg.SessionPepper)
		if err != nil {
			return failRuntime(err)
		}
		portForwards, err = coder.NewPortForwardManager(coderClient)
		if err != nil {
			return failRuntime(err)
		}
		previewGateway, err = preview.NewGateway(cfg.PreviewDomain, previewTokens, func(ctx context.Context, routeID string) (preview.Route, error) {
			record, err := state.PreviewRouteByID(ctx, routeID)
			if err != nil {
				return preview.Route{}, err
			}
			if record.Port < 1024 || record.Port > 65535 {
				return preview.Route{}, core.ErrInvalid
			}
			return preview.Route{
				ID: record.ID, OwnerID: record.OwnerID, WorkspaceID: record.WorkspaceID,
				Port: uint16(record.Port), Process: record.ProcessName, Host: record.WorkspaceHost,
				CreatedAt: record.CreatedAt, RevokedAt: record.RevokedAt,
			}, nil
		}, portForwards)
		if err != nil {
			_ = portForwards.Close()
			return failRuntime(err)
		}
	}
	health := compositeHealth{database: pool, coder: coderClient}
	var maintenanceCoordinator *maintenance.Coordinator
	if cfg.MaintenanceEnabled {
		maintenanceStore, storeErr := postgres.NewMaintenanceStore(pool)
		if storeErr != nil {
			return failRuntime(storeErr)
		}
		maintenanceCoordinator, err = maintenance.New(
			maintenanceStore, workspaceStore, checkpointService, workspaceService, controller, state, health, metricsRegistry,
			maintenance.Config{
				Weekday: cfg.MaintenanceWeekday, HourUTC: cfg.MaintenanceHourUTC,
				WarningLead: cfg.MaintenanceWarningLead, UrgentWarningLead: cfg.MaintenanceUrgentLead,
				ScanInterval: cfg.MaintenanceScanInterval,
			},
		)
		if err != nil {
			return failRuntime(err)
		}
		if err := maintenanceCoordinator.Recover(ctx); err != nil {
			return failRuntime(err)
		}
	}

	app, err := application.New(application.Config{
		GitHubConfigured: cfg.GitHubEnabled, APNSConfigured: cfg.APNSEnabled,
		PreviewsConfigured:       previewsConfigured,
		MaximumRunningWorkspaces: cfg.MaxRunning, TerminalWebSocketURL: terminalURL,
		PreviewDomain: cfg.PreviewDomain, PreviewAccessTTL: 5 * time.Minute,
		APNSTopic: cfg.IOSBundleID, DefaultDeviceName: "iPhone or iPad",
		FileSearchLimit: 200, InitialTerminalSize: terminal.Size{Rows: 24, Columns: 80},
	}, application.Dependencies{
		Health:   health,
		Passkeys: passkeyService, Bootstrap: bootstrap, Sessions: sessions,
		Repositories: repositories, Connections: repositories, Workspaces: workspaceService, WorkspaceStore: workspaceStore,
		SetupReviews: setupReviews, State: state, GitHub: githubClient, Coder: coderRuntime, Terminals: terminalManager,
		PreviewTokens: previewTokens, PreviewTunnels: portForwards,
		Notifications: notificationDispatcher,
		Checkpoints:   checkpointService, Maintenance: maintenanceCoordinator,
	})
	if err != nil {
		if portForwards != nil {
			_ = portForwards.Close()
		}
		return failRuntime(err)
	}
	if err := workspaceService.ConfigureDeletionBoundary(app); err != nil {
		return failRuntime(err)
	}
	if err := workspaceService.ConfigureSuspensionBoundary(app); err != nil {
		return failRuntime(err)
	}
	authenticator, err := application.NewAuthenticator(sessions)
	if err != nil {
		return failRuntime(err)
	}
	api, err := httpapi.New(httpapi.Options{Application: app, Authenticator: authenticator, TerminalWebSocket: terminalGateway, Metrics: metricsRegistry})
	if err != nil {
		return failRuntime(err)
	}
	return &serverRuntime{
		pool: pool, serveLease: serveLease, terminals: terminalManager, portForwards: portForwards, notifications: notificationDispatcher, checkpoints: checkpointScheduler, lifecycle: lifecycleCoordinator,
		maintenance: maintenanceCoordinator, metrics: metricsRegistry, attachments: attachmentJanitor,
		handler: hostRouter{
			apiHost: strings.ToLower(cfg.APIHost), previewDomain: strings.ToLower(cfg.PreviewDomain),
			production: cfg.Environment == "production", api: api, preview: previewGateway, webhook: webhook,
		},
	}, nil
}

func runMaintenanceScheduler(ctx context.Context, coordinator *maintenance.Coordinator, pool *pgxpool.Pool, interval time.Duration, report func(error)) {
	if report == nil {
		report = func(error) {}
	}
	run := func() {
		ownerID, err := singleOwnerID(ctx, pool)
		if errors.Is(err, pgx.ErrNoRows) {
			return
		}
		if err != nil {
			report(err)
			return
		}
		if _, err := coordinator.ScheduleWeekly(ctx, ownerID); err != nil && !errors.Is(err, core.ErrConflict) {
			report(err)
		}
		if err := coordinator.RunOnce(ctx); err != nil && ctx.Err() == nil {
			report(err)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

type compositeHealth struct {
	database interface{ Ping(context.Context) error }
	coder    interface{ Health(context.Context) error }
}

func (h compositeHealth) Ping(ctx context.Context) error {
	if err := h.database.Ping(ctx); err != nil {
		return errors.New("database unavailable")
	}
	if err := h.coder.Health(ctx); err != nil {
		return errors.New("workspace provider unavailable")
	}
	return nil
}

type unavailableEnvironmentDetector struct{}

func (unavailableEnvironmentDetector) Detect(context.Context, string, core.Repository, string) (workspace.Environment, error) {
	return workspace.Environment{}, fmt.Errorf("%w: GitHub integration is not configured", core.ErrPrecondition)
}

type hostRouter struct {
	apiHost, previewDomain string
	production             bool
	api, preview, webhook  http.Handler
}

func (h hostRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	host = strings.TrimSuffix(host, ".")
	if h.preview != nil && h.previewDomain != "" && strings.HasSuffix(host, "."+strings.TrimSuffix(h.previewDomain, ".")) {
		h.preview.ServeHTTP(w, r)
		return
	}
	if h.production && host != strings.TrimSuffix(h.apiHost, ".") {
		http.NotFound(w, r)
		return
	}
	if h.webhook != nil && r.URL.Path == "/v1/github/webhook" {
		h.webhook.ServeHTTP(w, r)
		return
	}
	h.api.ServeHTTP(w, r)
}

func websocketURL(publicOrigin string) (string, error) {
	value, err := url.Parse(publicOrigin)
	if err != nil || value.Host == "" {
		return "", errors.New("invalid public origin")
	}
	switch value.Scheme {
	case "http":
		value.Scheme = "ws"
	case "https":
		value.Scheme = "wss"
	default:
		return "", errors.New("public origin must use HTTP or HTTPS")
	}
	value.Path = httpapi.TerminalWebSocketPath
	value.RawPath, value.RawQuery, value.Fragment = "", "", ""
	return value.String(), nil
}

func singleOwnerID(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	rows, err := pool.Query(ctx, `SELECT id FROM users ORDER BY created_at, id LIMIT 2`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	owners := make([]string, 0, 2)
	for rows.Next() {
		var owner string
		if err := rows.Scan(&owner); err != nil {
			return "", err
		}
		owners = append(owners, owner)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(owners) == 0 {
		return "", pgx.ErrNoRows
	}
	if len(owners) != 1 {
		return "", errors.New("single-owner invariant violated")
	}
	return owners[0], nil
}

// safeError bounds log output and strips control characters. Underlying
// provider response bodies and secrets are never included by constructors.
func safeError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, err.Error())
	if len(value) > 500 {
		value = value[:500]
	}
	return value
}
