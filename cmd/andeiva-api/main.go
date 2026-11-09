package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/AsterG/andeiva/internal/httpserver"
)

func main() {
	os.Exit(run())
}

func run() int {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(os.Args) > 1 && (len(os.Args) != 2 || os.Args[1] != "--healthcheck") {
		logger.Error("startup_failed", "code", "ANDEIVA_INVALID_ARGUMENT")
		return 2
	}
	address, err := httpserver.ParseAddress(os.Getenv("ANDEIVA_LISTEN_ADDR"))
	if err != nil {
		logger.Error("startup_failed", "code", "ANDEIVA_INVALID_LISTEN_ADDRESS")
		return 2
	}
	if len(os.Args) == 2 {
		if err := httpserver.Probe(context.Background(), address); err != nil {
			logger.Error("healthcheck_failed", "code", "ANDEIVA_HEALTHCHECK_FAILED")
			return 1
		}
		return 0
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		logger.Error("startup_failed", "code", "ANDEIVA_LISTEN_FAILED")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("process_started", "mode", "scaffold")
	if err := httpserver.Serve(ctx, listener); err != nil {
		logger.Error("process_failed", "code", "ANDEIVA_SERVER_FAILED")
		return 1
	}
	logger.Info("process_stopped")
	return 0
}
