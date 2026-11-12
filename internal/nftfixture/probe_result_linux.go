package nftfixture

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

func checkListenerControls(ctx context.Context, label string, probe func(context.Context, string, int) (bool, error)) error {
	for _, protocol := range []string{"tcp", "udp"} {
		for port := 18080; port <= 18082; port++ {
			ok, err := probe(ctx, protocol, port)
			if err != nil || !ok {
				if err == nil {
					err = errors.New("no echo response")
				}
				return fmt.Errorf("%s: %s/%d: %w", label, protocol, port, errors.Join(err, ctx.Err()))
			}
		}
	}
	return nil
}

func probeCommandResult(ctx context.Context, err error, output string) (bool, error) {
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 10 {
		return false, nil
	}
	// CommandContext can report a killed child without wrapping its context.
	// Keep the existing exit protocol; enrich only an already failed command.
	return false, fmt.Errorf("ANDEIVA_NFT_PROBE_FAILED: %w: %s", errors.Join(err, ctx.Err()), output)
}
