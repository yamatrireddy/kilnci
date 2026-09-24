// SPDX-License-Identifier: Apache-2.0

// Package store is Kiln's PostgreSQL persistence layer.
//
// All SQL lives in queries/*.sql and is compiled by sqlc into db/ (generated,
// never hand-edited). This package wraps those queries, returns domain types,
// and maps database errors to domain errors so that driver errors such as
// pgx.ErrNoRows never leak past it. Every method on tenant data takes the
// org ID as a required argument.
//
// Transactions are carried in the context: InTx starts one and every store
// call made with the derived context joins it. Services open transactions;
// handlers never touch the store.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
	"github.com/yamatrireddy/kilnci/server/migrations"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/store")

// Store is the persistence layer. It is safe for concurrent use.
type Store struct {
	pool *pgxpool.Pool
}

// Options configures Open.
type Options struct {
	URL      string
	MaxConns int32
}

// Open connects to PostgreSQL and verifies the connection.
func Open(ctx context.Context, opts Options) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(opts.URL)
	if err != nil {
		// Never include err or the URL: both can contain the password.
		return nil, errors.New("open database: invalid connection string")
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	// Bound every statement so a stuck query cannot pin a connection forever.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "60000"
	cfg.ConnConfig.RuntimeParams["application_name"] = "kiln-server"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", redactConnErr(err))
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", redactConnErr(err))
	}
	return &Store{pool: pool}, nil
}

// redactConnErr drops connection details from pgx connect errors, whose text
// can include the host, user, and database name.
func redactConnErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return fmt.Errorf("server error %s", pgErr.Code)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	return errors.New("connection failed")
}

// Close releases all connections.
func (s *Store) Close() { s.pool.Close() }

// Ping reports whether the database is reachable (for /readyz).
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", redactConnErr(err))
	}
	return nil
}

// Migrate applies all pending embedded migrations.
func (s *Store) Migrate(ctx context.Context, log *slog.Logger) error {
	sqlDB := stdlib.OpenDBFromPool(s.pool)
	defer func() { _ = sqlDB.Close() }()
	return migrate(ctx, sqlDB, log)
}

func migrate(ctx context.Context, sqlDB *sql.DB, log *slog.Logger) error {
	// A session advisory lock lets several replicas (or test packages) start
	// at once without racing to apply the same migration.
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("create migration lock: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	results, err := provider.Up(ctx)
	for _, r := range results {
		log.InfoContext(ctx, "applied migration", "version", r.Source.Version, "duration", r.Duration)
	}
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

type txKey struct{}

// InTx runs fn in a transaction. Store calls made with the context passed to
// fn join the transaction. If a transaction is already active in ctx, fn joins
// it rather than starting a nested one. The transaction commits if fn returns
// nil and rolls back otherwise.
func (s *Store) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return fn(ctx)
	}
	ctx, span := tracer.Start(ctx, "store.InTx")
	defer span.End()
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		return fn(context.WithValue(ctx, txKey{}, tx))
	})
	if err != nil {
		span.SetStatus(codes.Error, "transaction failed")
		return err //nolint:wrapcheck // fn's errors are already wrapped by the caller; begin/commit errors are rare
	}
	return nil
}

// q returns queries bound to the active transaction, or to the pool.
func (s *Store) q(ctx context.Context) *db.Queries {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return db.New(tx)
	}
	return db.New(s.pool)
}

// PostgreSQL error codes we translate.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
	pgCheckViolation      = "23514"
)

// mapErr translates database errors into domain errors at the store boundary.
func mapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%s: %w", op, domain.ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgUniqueViolation:
			return fmt.Errorf("%s: %w", op, domain.ErrConflict)
		case pgForeignKeyViolation:
			return fmt.Errorf("%s: %w", op, domain.ErrNotFound)
		case pgCheckViolation:
			return fmt.Errorf("%s: %w", op, domain.ErrValidation)
		}
		// Keep the code and constraint for server logs; the message can echo data.
		return fmt.Errorf("%s: postgres error %s (%s)", op, pgErr.Code, strings.TrimSpace(pgErr.ConstraintName))
	}
	return fmt.Errorf("%s: %w", op, err)
}
