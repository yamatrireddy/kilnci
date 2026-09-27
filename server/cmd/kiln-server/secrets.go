// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/yamatrireddy/kilnci/server/internal/platform/config"
	"github.com/yamatrireddy/kilnci/server/internal/platform/httpclient"
	"github.com/yamatrireddy/kilnci/server/internal/secrets"
	secretsvc "github.com/yamatrireddy/kilnci/server/internal/service/secrets"
)

// openKeyring builds the KEK provider (ADR-0009 §2) and returns the keyring
// plus the key IDs it can unwrap with. It returns a nil keyring when no
// provider is configured.
func openKeyring(ctx context.Context, cfg config.Secrets, log *slog.Logger) (secretsvc.Keyring, []string, error) {
	switch cfg.Provider {
	case config.SecretsProviderLocal:
		cur, prev, err := cfg.MasterKeys()
		if err != nil {
			return nil, nil, err //nolint:wrapcheck // user-facing, key-free
		}
		w, err := secrets.NewLocalWrapper(cur, prev)
		clear(cur)
		clear(prev)
		if err != nil {
			return nil, nil, fmt.Errorf("secrets: %w", err)
		}
		return secrets.NewKeyring(w, 0), w.KeyIDs(), nil
	case config.SecretsProviderVault:
		v := cfg.Vault
		var pool *x509.CertPool
		if v.CACertFile != "" {
			pem, err := os.ReadFile(v.CACertFile)
			if err != nil {
				return nil, nil, errors.New("KILN_VAULT_CACERT_FILE: cannot read file")
			}
			pool = x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, nil, errors.New("KILN_VAULT_CACERT_FILE: no PEM certificates found")
			}
		}
		// A dedicated client: its own private-range allowlist and CA, so a
		// private Vault never widens the egress policy of other clients.
		client := httpclient.New(httpclient.Options{AllowedPrefixes: v.AllowedPrefixes, RootCAs: pool, UserAgent: "kiln-server/vault"})
		w, err := secrets.NewVaultWrapper(secrets.VaultOptions{
			Client: client, Addr: v.Addr, Mount: v.Mount, Key: v.TransitKey, TokenFile: v.TokenFile, Namespace: v.Namespace,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("secrets: %w", err)
		}
		info, err := w.Check(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("secrets: check Vault Transit key: %w", err)
		}
		if info.DeletionAllowed {
			log.WarnContext(ctx, "the Vault Transit key allows deletion; deleting it destroys every stored secret")
		}
		return secrets.NewKeyring(w, 0), w.KeyIDs(info), nil
	default:
		log.WarnContext(ctx, "pipeline secrets disabled: set KILN_SECRETS_PROVIDER (local or vault), see ADR-0009")
		return nil, nil, nil
	}
}
