//go:build !linux

package main

import "errors"

func run(_ []string) error { return errors.New("ANDEIVA_NFT_REQUIRES_DEBIAN_LAB") }
