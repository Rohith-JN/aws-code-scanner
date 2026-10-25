package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestConsumePush(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		for _, tt := range []struct {
			name, stream string
			wantErr      bool
		}{
			{"success", "{\"id\":\"layer\",\"status\":\"Pushed\"}\n{\"status\":\"digest: sha256:abc\"}\n", false},
			{"daemon error", `{"error":"denied"}`, true},
			{"error detail", `{"errorDetail":{"message":"unauthorized"}}`, true},
			{"truncated stream", `{"status":`, true},
		} {
			t.Run(tt.name, func(t *testing.T) {
				var out bytes.Buffer
				err := consumePush(strings.NewReader(tt.stream), &out, verbose)
				if (err != nil) != tt.wantErr {
					t.Fatalf("error = %v, want error %v", err, tt.wantErr)
				}
				if tt.name == "success" && strings.Contains(out.String(), "layer: Pushed") != verbose {
					t.Fatalf("unexpected progress output: %s", &out)
				}
			})
		}
	}
}

type pushTestStream struct {
	io.Reader
	closed bool
}

func (s *pushTestStream) Close() error {
	s.closed = true
	return nil
}

func TestPushRetriesTransientStreamFailures(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		var out bytes.Buffer
		first := &pushTestStream{Reader: strings.NewReader(`{"error":"failed to copy: write tcp 192.168.65.3:41806->192.168.65.1:3128: write: broken pipe"}`)}
		second := &pushTestStream{Reader: strings.NewReader(`{"status":"digest: sha256:abc"}`)}
		calls := 0
		err := pushWithRetry(context.Background(), func(context.Context) (io.ReadCloser, error) {
			calls++
			if calls == 1 {
				return first, nil
			}
			if !first.closed {
				t.Fatal("previous stream was not closed before retry")
			}
			return second, nil
		}, &out, verbose, []time.Duration{0, 0})
		if err != nil || calls != 2 || !second.closed {
			t.Fatalf("error=%v calls=%d second closed=%v", err, calls, second.closed)
		}
		if !strings.Contains(out.String(), "attempt 1/3") {
			t.Fatalf("missing retry notice: %s", &out)
		}
	}
}

func TestPushRetryPolicy(t *testing.T) {
	for _, tt := range []struct {
		name    string
		err     error
		wantTry int
	}{
		{"connection reset", errors.New("connection reset by peer"), 3},
		{"truncated stream", io.ErrUnexpectedEOF, 3},
		{"timeout", &timeoutPushError{}, 3},
		{"denied", errors.New("denied: not authorized"), 1},
		{"expired credentials", errors.New("ExpiredToken: token has expired"), 1},
		{"authentication despite nested transport message", errors.New("unauthorized: upstream connection reset"), 1},
		{"certificate", errors.New("x509: unknown certificate authority"), 1},
		{"missing image", errors.New("No such image"), 1},
		{"unknown failure", errors.New("invalid manifest"), 1},
		{"canceled", context.Canceled, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			err := pushWithRetry(context.Background(), func(context.Context) (io.ReadCloser, error) {
				calls++
				return nil, tt.err
			}, io.Discard, false, []time.Duration{0, 0})
			if !errors.Is(err, tt.err) || calls != tt.wantTry {
				t.Fatalf("error=%v calls=%d, want %d", err, calls, tt.wantTry)
			}
		})
	}
}

type timeoutPushError struct{}

func (*timeoutPushError) Error() string   { return "network timeout" }
func (*timeoutPushError) Timeout() bool   { return true }
func (*timeoutPushError) Temporary() bool { return true }

func TestPushCancellationDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := pushWithRetry(ctx, func(context.Context) (io.ReadCloser, error) {
		calls++
		return nil, errors.New("broken pipe")
	}, cancelPushWriter{cancel: cancel}, false, []time.Duration{time.Hour})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("error=%v calls=%d", err, calls)
	}
}

type cancelPushWriter struct {
	cancel context.CancelFunc
}

func (w cancelPushWriter) Write(p []byte) (int, error) {
	w.cancel()
	return len(p), nil
}

func TestPushDoesNotStartWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := pushWithRetry(ctx, func(context.Context) (io.ReadCloser, error) {
		t.Fatal("push started despite canceled context")
		return nil, nil
	}, io.Discard, false, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}
