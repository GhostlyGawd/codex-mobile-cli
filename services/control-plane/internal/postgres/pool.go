package postgres

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var identifierPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// PoolConfig contains bounded, fixed-resource PostgreSQL pool settings.
type PoolConfig struct {
	URL               string
	ApplicationName   string
	SearchPath        string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

// Open creates and pings a pgx pool without logging or returning the DSN.
func Open(ctx context.Context, settings PoolConfig) (*pgxpool.Pool, error) {
	if ctx == nil || strings.TrimSpace(settings.URL) == "" {
		return nil, errors.New("PostgreSQL context and URL are required")
	}
	if settings.SearchPath != "" && !identifierPattern.MatchString(settings.SearchPath) {
		return nil, errors.New("invalid PostgreSQL search path")
	}
	if strings.ContainsRune(settings.ApplicationName, '\x00') || len(settings.ApplicationName) > 63 {
		return nil, errors.New("invalid PostgreSQL application name")
	}
	config, err := pgxpool.ParseConfig(settings.URL)
	if err != nil {
		return nil, errors.New("parse PostgreSQL connection configuration")
	}
	applyPoolDefaults(config, settings)
	if config.MinConns > config.MaxConns {
		return nil, errors.New("PostgreSQL minimum connections exceed maximum")
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	return pool, nil
}

func applyPoolDefaults(config *pgxpool.Config, settings PoolConfig) {
	config.MaxConns = settings.MaxConns
	if config.MaxConns <= 0 {
		config.MaxConns = 16
	}
	config.MinConns = settings.MinConns
	if config.MinConns < 0 {
		config.MinConns = 0
	}
	config.MaxConnLifetime = settings.MaxConnLifetime
	if config.MaxConnLifetime <= 0 {
		config.MaxConnLifetime = 30 * time.Minute
	}
	config.MaxConnIdleTime = settings.MaxConnIdleTime
	if config.MaxConnIdleTime <= 0 {
		config.MaxConnIdleTime = 5 * time.Minute
	}
	config.HealthCheckPeriod = settings.HealthCheckPeriod
	if config.HealthCheckPeriod <= 0 {
		config.HealthCheckPeriod = 30 * time.Second
	}
	applicationName := settings.ApplicationName
	if applicationName == "" {
		applicationName = "codex-mobile-control-plane"
	}
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	if settings.SearchPath != "" {
		config.ConnConfig.RuntimeParams["search_path"] = settings.SearchPath
	}
}
