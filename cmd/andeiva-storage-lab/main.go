package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/AsterG/andeiva/internal/storagevol"
)

func main() { os.Exit(entry()) }
func entry() int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return run(ctx, os.Args[1:], os.Stdout, os.Geteuid())
}

func run(ctx context.Context, args []string, output io.Writer, uid int) int {
	if ctx == nil || output == nil {
		return 1
	}
	fail := func(code string, id string) int {
		_ = json.NewEncoder(output).Encode(map[string]string{"error_code": code, "id": id})
		return 1
	}
	if len(args) > 10 {
		return fail(storagevol.ErrInvalid.Error(), "")
	}
	total := 0
	for _, a := range args {
		total += len(a)
	}
	if total > 4096 {
		return fail(storagevol.ErrInvalid.Error(), "")
	}
	flags := flag.NewFlagSet("andeiva-storage-lab", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	authorized := flags.Bool("authorized-debian-lab", false, "")
	operation := flags.String("operation", "plan", "")
	id := flags.String("id", "", "")
	language := flags.String("lang", "en", "")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp && help[*language] != "" {
			_, err = io.WriteString(output, help[*language]+"\nandeiva-storage-lab --authorized-debian-lab --operation plan|prepare|inspect|harness-plan [--id ID] [--lang en|es|pt]\n")
			if err != nil {
				return 1
			}
			return 0
		}
		return fail(storagevol.ErrInvalid.Error(), "")
	}
	if uid != 0 || !*authorized {
		return fail("ANDEIVA_STORAGE_VOLUME_AUTHORIZATION", "")
	}
	if flags.NArg() != 0 || help[*language] == "" || (*operation != "inspect" && *operation != "harness-plan" && *id != "") {
		return fail(storagevol.ErrInvalid.Error(), "")
	}
	switch *operation {
	case "plan":
		if json.NewEncoder(output).Encode(storagevol.LabPlan()) != nil {
			return 1
		}
		return 0
	case "prepare":
		value, err := storagevol.Prepare(ctx)
		if err != nil {
			return fail(err.Error(), value.ID)
		}
		if json.NewEncoder(output).Encode(value) != nil {
			return 1
		}
		return 0
	case "inspect", "harness-plan":
		value, err := storagevol.Inspect(ctx, *id)
		if err != nil {
			return fail(err.Error(), value.ID)
		}
		if *operation == "harness-plan" {
			plan, encodeErr := storagevol.EncodeHarnessPlan(value)
			if encodeErr != nil {
				return fail(encodeErr.Error(), value.ID)
			}
			if _, encodeErr = io.WriteString(output, plan); encodeErr != nil {
				return 1
			}
			return 0
		}
		if json.NewEncoder(output).Encode(value) != nil {
			return 1
		}
		return 0
	default:
		return fail(storagevol.ErrInvalid.Error(), "")
	}
}

var help = map[string]string{
	"en": "Root-only development preparation of inactive laboratory volumes. Requires an authorized Debian laboratory; it never mounts or activates volumes and has no deletion command. The acknowledgement flag is not authentication.",
	"es": "Preparación de desarrollo exclusiva de root para volúmenes inactivos de laboratorio. Requiere un laboratorio Debian autorizado; no monta ni activa volúmenes y no incluye comandos de borrado. El indicador de autorización no es autenticación.",
	"pt": "Preparação de desenvolvimento exclusiva de root para volumes inativos de laboratório. Exige um laboratório Debian autorizado; não monta nem ativa volumes e não inclui comando de remoção. O indicador de autorização não é autenticação.",
}
