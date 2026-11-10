//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestShutdownWaitsForActiveHandler(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}), ReadHeaderTimeout: time.Second}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan error, 1)
	go func() {
		returned <- serveAndDrain(ctx, server, func() error { return server.Serve(listener) }, time.Second)
	}()
	client := &http.Client{Timeout: 2 * time.Second}
	response := make(chan error, 1)
	go func() {
		r, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = r.Body.Close()
			if r.StatusCode != http.StatusNoContent {
				err = errors.New("handler response lost")
			}
		}
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	select {
	case err := <-returned:
		t.Fatalf("dependencies could close before handler finished: %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	// A send releases this handler while the deferred close also covers failures.
	release <- struct{}{}
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not complete")
	}
	if err := <-response; err != nil {
		t.Fatal(err)
	}
}

func TestShutdownTimeoutClosesConnectionsAndReturnsError(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered, canceled := make(chan struct{}), make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}), ReadHeaderTimeout: time.Second}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan error, 1)
	go func() {
		returned <- serveAndDrain(ctx, server, func() error { return server.Serve(listener) }, 80*time.Millisecond)
	}()
	client := &http.Client{Timeout: 2 * time.Second}
	response := make(chan error, 1)
	go func() {
		r, err := client.Get("http://" + listener.Addr().String())
		if r != nil {
			_ = r.Body.Close()
		}
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	select {
	case err := <-returned:
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("timeout not propagated: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown exceeded its bounded drain")
	}
	select {
	case <-canceled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout did not cancel active request")
	}
	select {
	case err := <-response:
		if err == nil {
			t.Fatal("timed-out connection stayed open")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed-out client connection not closed")
	}
}
