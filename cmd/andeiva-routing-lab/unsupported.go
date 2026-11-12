//go:build !linux

package main

import "errors"

func run(_ []string) error { return errors.New("ANDEIVA_ROUTING_LAB_REQUIRES_DEBIAN13_AMD64") }
