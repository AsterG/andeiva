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
	if len(args) > 0 && (args[0] == previewruntime.RoutedDHCPOwnerRoleV3 || args[0] == previewruntime.RoutedDHCPDeferredOwnerRoleV4 || args[0] == previewruntime.RoutedSelectedPreflightRoleV4) {
		if len(args) != 1 {
			return previewruntime.ErrConfiguration
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		if args[0] == previewruntime.RoutedDHCPOwnerRoleV3 {
			return previewruntime.RunRoutedDHCPOwnerRoleV3(ctx)
		}
		if args[0] == previewruntime.RoutedSelectedPreflightRoleV4 {
			return previewruntime.RunRoutedSelectedPreflightRoleV4(ctx)
		}
		return previewruntime.RunRoutedDHCPDeferredOwnerRoleV4(ctx)
	}
	if len(args) > 0 && (args[0] == previewruntime.RoutedHelperRoleV3 || args[0] == previewruntime.RoutedAPIRoleV3) {
		if len(args) != 1 {
			return previewruntime.ErrConfiguration
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		return previewruntime.RunRoutedApplianceRoleV3(ctx, args[0])
	}
	if len(args) > 0 && (args[0] == previewruntime.RoutedMigrationPrepareRoleV3 || args[0] == previewruntime.RoutedMigrationInspectRoleV3 || args[0] == previewruntime.RoutedMigrationStateRoleV3 || args[0] == previewruntime.RoutedMigrationSourceRoleV3) {
		if len(args) != 1 {
			return previewruntime.ErrConfiguration
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		if args[0] == previewruntime.RoutedMigrationPrepareRoleV3 {
			return previewruntime.RunRoutedMigrationPrepareRoleV3(ctx)
		}
		if args[0] == previewruntime.RoutedMigrationInspectRoleV3 {
			return previewruntime.RunRoutedMigrationInspectRoleV3(ctx)
		}
		if args[0] == previewruntime.RoutedMigrationStateRoleV3 {
			return previewruntime.RunRoutedMigrationStateRoleV3(ctx)
		}
		return previewruntime.RunRoutedMigrationSourceRoleV3(ctx)
	}
	if len(args) == 1 && args[0] == previewruntime.RoutedIntegrityPrepareRoleV3 {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		return previewruntime.RunRoutedIntegrityPrepareRoleV3(ctx)
	}
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
	case "grouped-profile":
		result, err := previewruntime.ConvertRoutedMigrationProfileV3(ctx, c)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "grouped-prepare":
		result, err := previewruntime.PrepareRoutedMigrationV3(ctx, c)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "grouped-links":
		return previewruntime.PrepareRoutedNodeLinksV3(ctx, c, os.Stdin)
	case "grouped-retirement-slot":
		return previewruntime.PrepareRoutedRetirementSlotV3(ctx, c)
	case "grouped-scope-slot":
		return previewruntime.PrepareRoutedScopeRecoverySlotV3(ctx, c)
	case "grouped-accounts":
		digest, err := previewruntime.PrepareRoutedAccountsV3(ctx, c)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"accounts_sha256": digest})
	case "grouped-inspect":
		result, err := previewruntime.InspectRoutedMigrationV3(ctx, c)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "grouped-supervisor":
		return previewruntime.RunRoutedSupervisorV3(ctx, c)
	case "grouped-managed-supervisor":
		return previewruntime.RunRoutedManagedSupervisorV3(ctx, c)
	case "grouped-health":
		result, err := previewruntime.GroupedHealthV3(ctx, c)
		if encode := json.NewEncoder(os.Stdout).Encode(result); err == nil {
			err = encode
		}
		return err
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
		if e = previewruntime.LegacyRuntimeAllowedV3(); e != nil {
			return e
		}
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
