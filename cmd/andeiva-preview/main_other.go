//go:build !linux

package main

import "errors"

func run([]string) error { return errors.New("ANDEIVA_PREVIEW_UNSUPPORTED") }
