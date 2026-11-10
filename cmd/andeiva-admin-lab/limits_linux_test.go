package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestRequestAdmissionRejectsWithoutQueueing(t *testing.T) {
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	h := admitted(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { entered <- struct{}{}; <-release }))
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/firewall", nil))
		}()
	}
	for range 16 {
		<-entered
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/firewall", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	close(release)
	wg.Wait()
}
