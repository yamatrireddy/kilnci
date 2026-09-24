// SPDX-License-Identifier: Apache-2.0

package config

import "log/slog"

const redacted = "[REDACTED]"

// Secret holds a sensitive configuration value. Every formatting path (fmt,
// slog, JSON) prints a placeholder; only Reveal returns the value, which makes
// accidental logging of secrets hard and deliberate use easy to grep for.
type Secret struct {
	value string
}

// NewSecret wraps v.
func NewSecret(v string) Secret { return Secret{value: v} }

// Reveal returns the underlying value. Call it only at the point of use.
func (s Secret) Reveal() string { return s.value }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s.value == "" }

// String implements fmt.Stringer with a placeholder.
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer so %#v is redacted too.
func (s Secret) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON implements json.Marshaler with a placeholder.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler with a placeholder.
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
