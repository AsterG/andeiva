//go:build !linux

package main

func processUsage() (int64, int64, bool) { return 0, 0, false }
