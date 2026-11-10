package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/adminclient"
	"github.com/AsterG/andeiva/internal/configpoc"
)

var firewallCommands = []string{"list", "status", "stage", "validate", "commit", "confirm", "save", "rollback", "history", "help", "completion"}
var firewallText = map[string][3]string{
	"en": {"Authenticated firewall laboratory management. HTTPS and an explicit CA are required.", "Request failed. Check the connection, credentials, permissions and current revision.", "Stage requires a request JSON file (or - for stdin). Other mutations accept a request file or use the current generation. Credentials: Linux regular file, owner only, mode 0600. JSON output uses stable field names."},
	"es": {"Administración autenticada del firewall de laboratorio. Requiere HTTPS y una CA explícita.", "La solicitud falló. Revise conexión, credenciales, permisos y revisión actual.", "Stage requiere un archivo JSON de solicitud (o - para entrada estándar). Las otras mutaciones aceptan un archivo o usan la generación actual. Credenciales: archivo regular Linux, propietario actual, modo 0600. La salida JSON usa campos estables."},
	"pt": {"Administração autenticada do firewall de laboratório. Requer HTTPS e uma CA explícita.", "A solicitação falhou. Verifique conexão, credenciais, permissões e revisão atual.", "Stage requer um arquivo JSON de solicitação (ou - para entrada padrão). Outras mutações aceitam um arquivo ou usam a geração atual. Credenciais: arquivo regular Linux, proprietário atual, modo 0600. A saída JSON usa campos estáveis."},
}

func uniqueCommand(input string) (string, bool) {
	for _, command := range firewallCommands {
		if input == command {
			return command, true
		}
	}
	found := ""
	for _, command := range firewallCommands {
		if input != "" && strings.HasPrefix(command, input) {
			if found != "" {
				return "", false
			}
			found = command
		}
	}
	return found, found != ""
}
func runFirewall(args []string, locale string, stdin io.Reader, stdout, stderr io.Writer) int {
	text := firewallText[locale]
	fail := func(err error) int {
		code := "ANDEIVA_INVALID_ARGUMENT"
		var api *adminclient.APIError
		if errors.As(err, &api) {
			code = api.Code
		} else {
			for _, known := range []error{adminclient.ErrConfiguration, adminclient.ErrCredentials, adminclient.ErrTransport, adminclient.ErrResponse} {
				if errors.Is(err, known) {
					code = known.Error()
					break
				}
			}
		}
		fmt.Fprintln(stderr, code+":", text[1])
		return 2
	}
	if len(args) == 0 {
		args = []string{"help"}
	}
	command, ok := uniqueCommand(args[0])
	if !ok {
		return fail(nil)
	}
	if command == "help" && len(args) == 1 {
		fmt.Fprintln(stdout, text[0])
		fmt.Fprintln(stdout, "andeiva [--lang en|es|pt] firewall <list|status|stage|validate|commit|confirm|save|rollback|history>")
		fmt.Fprintln(stdout, "  --url https://HOST:PORT --ca-file FILE --credentials-file FILE")
		fmt.Fprintln(stdout, "  --request-file FILE|- [--confirm-seconds 30..120] [--target REVISION]")
		fmt.Fprintln(stdout, "  history [--before SEQUENCE] [--limit 1..100]")
		fmt.Fprintln(stdout, text[2])
		return 0
	}
	// Fixed, sourceable Bash completion does not evaluate external text.
	if command == "completion" && len(args) == 1 {
		fmt.Fprintln(stdout, `_andeiva_complete() { COMPREPLY=(); if [[ ${COMP_WORDS[1]} == firewall ]]; then COMPREPLY=( $(compgen -W 'list status stage validate commit confirm save rollback history help' -- "${COMP_WORDS[COMP_CWORD]}") ); else COMPREPLY=( $(compgen -W 'help status firewall' -- "${COMP_WORDS[COMP_CWORD]}") ); fi; }; complete -F _andeiva_complete andeiva`)
		return 0
	}
	options := map[string]string{}
	for i := 1; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return fail(nil)
		}
		key := args[i]
		switch key {
		case "--url", "--ca-file", "--credentials-file", "--request-file", "--confirm-seconds", "--target", "--before", "--limit":
		default:
			return fail(nil)
		}
		if _, exists := options[key]; exists || args[i+1] == "" {
			return fail(nil)
		}
		options[key] = args[i+1]
	}
	if command == "help" || command == "completion" || options["--url"] == "" || options["--ca-file"] == "" || options["--credentials-file"] == "" {
		return fail(nil)
	}
	readOnly := command == "list" || command == "status" || command == "history"
	if readOnly && (options["--request-file"] != "" || options["--target"] != "" || options["--confirm-seconds"] != "") {
		return fail(nil)
	}
	if command != "history" && (options["--before"] != "" || options["--limit"] != "") {
		return fail(nil)
	}
	if command != "commit" && options["--confirm-seconds"] != "" || command != "rollback" && options["--target"] != "" {
		return fail(nil)
	}
	limit := 50
	var before uint64
	var err error
	if options["--limit"] != "" {
		limit, err = strconv.Atoi(options["--limit"])
		if err != nil || limit < 1 || limit > 100 {
			return fail(nil)
		}
	}
	if options["--before"] != "" {
		before, err = strconv.ParseUint(options["--before"], 10, 64)
		if err != nil {
			return fail(nil)
		}
	}
	var request configpoc.Request
	if path := options["--request-file"]; path != "" {
		var reader io.Reader = stdin
		var file *os.File
		if path != "-" {
			file, err = os.Open(path)
			if err != nil {
				return fail(nil)
			}
			defer file.Close()
			stat, statErr := file.Stat()
			if statErr != nil || !stat.Mode().IsRegular() {
				return fail(nil)
			}
			reader = file
		}
		if reader == nil {
			return fail(nil)
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, 65537))
		if readErr != nil || len(data) > 65536 {
			return fail(nil)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
			return fail(nil)
		}
		if request.Operation != "" && request.Operation != command {
			return fail(nil)
		}
	}
	request.Operation = command
	if command == "stage" && request.Config == nil {
		return fail(nil)
	}
	if options["--target"] != "" {
		request.Target = options["--target"]
	}
	if command == "rollback" && request.Target == "" {
		return fail(nil)
	}
	if options["--confirm-seconds"] != "" {
		seconds, parseErr := strconv.Atoi(options["--confirm-seconds"])
		if parseErr != nil || seconds < 30 || seconds > 120 {
			return fail(nil)
		}
		request.ConfirmFor = time.Duration(seconds) * time.Second
	}
	ca, err := adminclient.ReadCA(options["--ca-file"])
	if err != nil {
		return fail(err)
	}
	client, err := adminclient.New(options["--url"], ca)
	if err != nil {
		return fail(err)
	}
	credentials, err := adminclient.ReadCredentials(options["--credentials-file"])
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err = client.Login(ctx, credentials); err != nil {
		return fail(err)
	}
	credentials = adminclient.Credentials{}
	var result any
	if command == "history" {
		result, err = client.History(ctx, before, limit)
	} else if readOnly {
		result, err = client.State(ctx)
	} else {
		if options["--request-file"] == "" {
			state, stateErr := client.State(ctx)
			if stateErr != nil {
				err = stateErr
			} else {
				request.ExpectedGeneration = state.Snapshot.Generation
			}
		}
		if err == nil && request.Key == "" {
			var key [16]byte
			if _, randomErr := rand.Read(key[:]); randomErr != nil {
				err = adminclient.ErrConfiguration
			} else {
				request.Key = hex.EncodeToString(key[:])
			}
		}
		if err == nil {
			result, err = client.Execute(ctx, request)
		}
	}
	// Cleanup has its own deadline even if the operation timed out.
	logoutCtx, logoutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer logoutCancel()
	logoutErr := client.Logout(logoutCtx)
	if err != nil {
		return fail(err)
	}
	if encodeErr := json.NewEncoder(stdout).Encode(result); encodeErr != nil {
		return fail(adminclient.ErrResponse)
	}
	if logoutErr != nil {
		return fail(logoutErr)
	}
	return 0
}
