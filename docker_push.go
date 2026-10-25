package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Each retry opens a fresh daemon stream. Already committed registry layers can
// be reused; a failed stream must be closed before another push begins.
func pushWithRetry(ctx context.Context, push func(context.Context) (io.ReadCloser, error), out io.Writer, verbose bool, retryDelays []time.Duration) error {
	attempts := len(retryDelays) + 1
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		stream, err := push(ctx)
		if err == nil {
			if stream == nil {
				return errors.New("Docker returned no push response")
			}
			err = consumePush(stream, out, verbose)
		}
		if stream != nil {
			stream.Close()
		}
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt == attempts || !isTransientPushError(err) {
			return fmt.Errorf("attempt %d/%d: %w", attempt, attempts, err)
		}
		delay := retryDelays[attempt-1]
		fmt.Fprintf(out, "Docker upload interrupted (attempt %d/%d): %v\nRetrying in %s...\n", attempt, attempts, err, delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func isTransientPushError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// Daemon-side upload failures arrive as JSON strings, not typed Go errors.
	// Check permanent failures first so a nested timeout cannot mask an auth error.
	message := strings.ToLower(err.Error())
	for _, permanent := range []string{"unauthorized", "authentication required", "access denied", "accessdenied", "denied:", "forbidden", "no basic auth credentials", "expiredtoken", "token has expired", "certificate", "x509", "no such image", "repository does not exist"} {
		if strings.Contains(message, permanent) {
			return false
		}
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	for _, transient := range []string{"broken pipe", "connection reset", "connection aborted", "unexpected eof", "i/o timeout", "tls handshake timeout", "temporary failure in name resolution", "use of closed network connection", "502 bad gateway", "503 service unavailable", "504 gateway timeout"} {
		if strings.Contains(message, transient) {
			return true
		}
	}
	return false
}

// Docker can return HTTP success and still report a push failure in its stream.
// Consume exactly one push stream and check it in both verbose and quiet mode.
func consumePush(stream io.Reader, out io.Writer, verbose bool) error {
	decoder := json.NewDecoder(stream)
	for {
		var message struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
			Status string `json:"status"`
			ID     string `json:"id"`
		}
		if err := decoder.Decode(&message); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("reading Docker push response: %w", err)
		}
		if message.Error == "" {
			message.Error = message.ErrorDetail.Message
		}
		if message.Error != "" {
			return fmt.Errorf("%s", message.Error)
		}
		if verbose && message.Status != "" {
			if message.ID != "" {
				fmt.Fprintf(out, "%s: %s\n", message.ID, message.Status)
			} else {
				fmt.Fprintln(out, message.Status)
			}
		}
	}
}
