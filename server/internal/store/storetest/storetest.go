// SPDX-License-Identifier: Apache-2.0

//go:build integration

// Package storetest provides a migrated PostgreSQL store for integration tests.
//
// If KILN_TEST_DATABASE_URL is set (CI service container, or `make infra-up`),
// that database is used; otherwise a throwaway container is started with
// testcontainers and a random password. One database is shared per test
// binary: tests isolate themselves with unique IDs and slugs (see Unique)
// rather than truncating, because the audit log is append-only by design.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

var (
	once     sync.Once
	shared   *store.Store
	errSetup error
)

// New returns the shared, migrated store. It fails the test (never skips) if
// no database can be provisioned, so integration runs cannot silently pass.
func New(t *testing.T) *store.Store {
	t.Helper()
	once.Do(func() { shared, errSetup = setup() })
	if errSetup != nil {
		t.Fatalf("integration database: %v", errSetup)
	}
	return shared
}

func setup() (*store.Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := os.Getenv("KILN_TEST_DATABASE_URL")
	if dsn == "" {
		ctr, err := postgres.Run(ctx, "postgres:18-alpine",
			postgres.WithDatabase("kiln"),
			postgres.WithUsername("kiln"),
			postgres.WithPassword(Unique("pw")), // random per run; never a fixed credential
			postgres.BasicWaitStrategies(),
		)
		if err != nil {
			return nil, err //nolint:wrapcheck // test setup
		}
		// The container is removed by the testcontainers reaper when the
		// test binary exits.
		if dsn, err = ctr.ConnectionString(ctx, "sslmode=disable"); err != nil {
			return nil, err //nolint:wrapcheck // test setup
		}
	}
	s, err := store.Open(ctx, store.Options{URL: dsn, MaxConns: 10})
	if err != nil {
		return nil, err //nolint:wrapcheck // test setup
	}
	if err := s.Migrate(ctx, logging.Discard()); err != nil {
		return nil, err //nolint:wrapcheck // test setup
	}
	return s, nil
}

// Unique returns prefix plus 12 random lowercase hex characters, valid as a
// slug, for isolating test data in the shared database.
func Unique(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return strings.ToLower(prefix) + "-" + hex.EncodeToString(b)
}
