// SPDX-License-Identifier: Apache-2.0

// Package bus carries small "something changed" notifications between
// server components and replicas (ADR-0007 §3). Messages hold IDs only,
// never log content or secrets; subscribers re-read state from the store,
// so a lost or duplicated notification is harmless.
//
// Backends: in-process (single replica, --embedded) and NATS with TLS and
// credentials. Subjects are dot-separated and built from server IDs.
package bus

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// Bus publishes and subscribes to notifications.
type Bus interface {
	Publish(ctx context.Context, subject string) error
	// Subscribe returns a channel that receives a value (coalesced) whenever
	// subject is published, until cancel is called.
	Subscribe(subject string) (ch <-chan struct{}, cancel func(), err error)
	Close() error
}

var subjectPattern = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-zA-Z0-9_-]+)*$`)

// ErrInvalidSubject means a subject was not built from server IDs.
var ErrInvalidSubject = errors.New("invalid bus subject")

// JobLogs returns the subject notified when a job's log or status changes.
func JobLogs(orgID, jobID string) string {
	return "kiln.orgs." + orgID + ".jobs." + jobID + ".logs"
}

// InProcess is a Bus for a single server process.
type InProcess struct {
	mu   sync.Mutex
	subs map[string]map[*chan struct{}]struct{}
}

// NewInProcess returns an in-process bus.
func NewInProcess() *InProcess {
	return &InProcess{subs: map[string]map[*chan struct{}]struct{}{}}
}

// Publish notifies every current subscriber of subject without blocking.
func (b *InProcess) Publish(_ context.Context, subject string) error {
	if !subjectPattern.MatchString(subject) {
		return ErrInvalidSubject
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[subject] {
		select {
		case *ch <- struct{}{}:
		default: // already pending: notifications coalesce
		}
	}
	return nil
}

// Subscribe registers for notifications on subject.
func (b *InProcess) Subscribe(subject string) (<-chan struct{}, func(), error) {
	if !subjectPattern.MatchString(subject) {
		return nil, nil, ErrInvalidSubject
	}
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	if b.subs[subject] == nil {
		b.subs[subject] = map[*chan struct{}]struct{}{}
	}
	b.subs[subject][&ch] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			delete(b.subs[subject], &ch)
			if len(b.subs[subject]) == 0 {
				delete(b.subs, subject)
			}
		})
	}, nil
}

// Close is a no-op.
func (b *InProcess) Close() error { return nil }

// NATSOptions configures the NATS backend.
type NATSOptions struct {
	URL string
	// CredsFile is a NATS credentials file (JWT + NKey seed); or use
	// User/Password.
	CredsFile string
	User      string
	Password  string
	// TLS is required unless Insecure is set (development only).
	TLS      *tls.Config
	Insecure bool
}

// NATS is a Bus backed by a NATS server.
type NATS struct {
	nc *nats.Conn
}

// NewNATS connects to NATS.
func NewNATS(o NATSOptions) (*NATS, error) {
	opts := []nats.Option{
		nats.Name("kiln-server"),
		nats.Timeout(5 * time.Second),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
	}
	if !o.Insecure {
		cfg := o.TLS
		if cfg == nil {
			cfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		opts = append(opts, nats.Secure(cfg))
	}
	switch {
	case o.CredsFile != "":
		opts = append(opts, nats.UserCredentials(o.CredsFile))
	case o.User != "":
		opts = append(opts, nats.UserInfo(o.User, o.Password))
	}
	nc, err := nats.Connect(o.URL, opts...)
	if err != nil {
		// The URL may carry credentials; do not echo it.
		return nil, fmt.Errorf("connect to NATS: %w", redact(err))
	}
	return &NATS{nc: nc}, nil
}

func redact(err error) error {
	switch {
	case errors.Is(err, nats.ErrNoServers):
		return nats.ErrNoServers
	case errors.Is(err, nats.ErrAuthorization):
		return nats.ErrAuthorization
	default:
		return errors.New("connection failed")
	}
}

// Publish sends an empty notification on subject.
func (b *NATS) Publish(_ context.Context, subject string) error {
	if !subjectPattern.MatchString(subject) {
		return ErrInvalidSubject
	}
	if err := b.nc.Publish(subject, nil); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	return nil
}

// Subscribe registers for notifications on subject.
func (b *NATS) Subscribe(subject string) (<-chan struct{}, func(), error) {
	if !subjectPattern.MatchString(subject) {
		return nil, nil, ErrInvalidSubject
	}
	ch := make(chan struct{}, 1)
	sub, err := b.nc.Subscribe(subject, func(*nats.Msg) {
		select {
		case ch <- struct{}{}:
		default:
		}
	})
	if err != nil {
		return nil, nil, fmt.Errorf("subscribe: %w", err)
	}
	return ch, func() { _ = sub.Unsubscribe() }, nil
}

// Ping reports whether the connection is up (for /readyz).
func (b *NATS) Ping(context.Context) error {
	if !b.nc.IsConnected() {
		return errors.New("nats: not connected")
	}
	return nil
}

// Close drains and closes the connection.
func (b *NATS) Close() error {
	b.nc.Close()
	return nil
}
