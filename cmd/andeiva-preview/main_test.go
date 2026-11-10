package main

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestFixtureExitStatusesPreserved(t *testing.T) {
	for _, code := range []int{0, 1, 2, 10} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var stderr bytes.Buffer
			var err error
			if code != 0 {
				err = fmt.Errorf("fixture subprocess: %w", roleExit(code))
			}
			if got := finish(err, &stderr); got != code {
				t.Fatalf("fixture status %d became %d", code, got)
			}
			if stderr.Len() != 0 {
				t.Fatalf("fixture outcome acquired a public command error: %q", stderr.String())
			}
		})
	}
}

func TestPublicFailureRemainsGeneric(t *testing.T) {
	var stderr bytes.Buffer
	if code := finish(errors.New("private runtime diagnostics"), &stderr); code != 1 {
		t.Fatalf("public failure status: %d", code)
	}
	if stderr.String() != "ANDEIVA_PREVIEW_UNAVAILABLE\n" {
		t.Fatalf("public diagnostic changed: %q", stderr.String())
	}
}
