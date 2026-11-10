//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/AsterG/andeiva/internal/nftfixture"
	"github.com/AsterG/andeiva/internal/previewnet"
	"github.com/AsterG/andeiva/internal/previewruntime"
)

func run(args []string) error {
	if handled, code := nftfixture.HandleRole(args); handled {
		if code != 0 {
			return roleExit(code)
		}
		return nil
	}
	if len(args) == 0 {
		return previewruntime.ErrConfiguration
	}
	operation := args[0]
	flags := flag.NewFlagSet("andeiva-preview", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", previewruntime.ConfigPath, "validated configuration")
	protocol := flags.String("protocol", "tcp", "probe protocol")
	port := flags.Int("port", 18080, "probe port")
	reverse := flags.Bool("reverse", false, "reverse probe")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return previewruntime.ErrConfiguration
	}
	c, e := previewruntime.LoadConfig(*path)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	switch operation {
	case "provision":
		if e = previewruntime.Provision(c); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]bool{"provisioned": true})
	case "api":
		return previewruntime.API(ctx, c)
	case "helper":
		return previewruntime.Helper(ctx, c)
	case "health":
		result, e := previewruntime.Health(ctx, c)
		if encode := json.NewEncoder(os.Stdout).Encode(result); e == nil {
			e = encode
		}
		return e
	case "namespaces":
		ids, e := previewruntime.LoadIdentities(c)
		if e != nil {
			return e
		}
		executable, e := os.Executable()
		if e != nil {
			return e
		}
		return previewnet.Run(ctx, previewnet.Options{Executable: executable, UID: ids.HelperUID, GID: ids.IPCGID, Log: os.Stdout})
	case "probe":
		op := "probe"
		if *reverse {
			op = "probe-reverse"
		}
		reply, e := previewnet.Request(ctx, previewnet.ControlRequest{Operation: op, Protocol: *protocol, Port: *port})
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(reply)
	default:
		return previewruntime.ErrConfiguration
	}
}
