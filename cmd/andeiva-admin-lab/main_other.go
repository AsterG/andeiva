//go:build !linux

package main

import "errors"

func run([]string) error { return errors.New("ANDEIVA_ADMIN_LAB_REQUIRES_DEBIAN") }
