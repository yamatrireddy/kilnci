// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestInProcess_NotifiesAndCoalesces(t *testing.T) {
	b := NewInProcess()
	ctx := context.Background()
	subj := JobLogs("01ORG", "01JOB")
	ch, cancel, err := b.Subscribe(subj)
	if err != nil {
		t.Fatal(err)
	}
	other, cancelOther, _ := b.Subscribe(JobLogs("01ORG", "02JOB"))
	defer cancelOther()
	for range 3 {
		if err := b.Publish(ctx, subj); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-ch:
	default:
		t.Fatal("no notification")
	}
	select {
	case <-ch:
		t.Fatal("notifications were not coalesced")
	default:
	}
	select {
	case <-other:
		t.Fatal("other subject notified")
	default:
	}
	cancel()
	cancel() // idempotent
	if err := b.Publish(ctx, subj); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
		t.Fatal("notified after unsubscribe")
	default:
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInProcess_RejectsBadSubjects(t *testing.T) {
	b := NewInProcess()
	for _, s := range []string{"", "a..b", "a.*", "a.>", "a b", ".a"} {
		if err := b.Publish(context.Background(), s); !errors.Is(err, ErrInvalidSubject) {
			t.Errorf("Publish(%q) = %v", s, err)
		}
		if _, _, err := b.Subscribe(s); !errors.Is(err, ErrInvalidSubject) {
			t.Errorf("Subscribe(%q) = %v", s, err)
		}
	}
}

func TestNewNATS_DoesNotEchoCredentials(t *testing.T) {
	_, err := NewNATS(NATSOptions{URL: "nats://user:hunter2@127.0.0.1:1", Insecure: true})
	if err == nil {
		t.Fatal("connected to a closed port")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error echoes credentials: %v", err)
	}
}
