package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/adminclient"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkplan"
)

var configurationText = map[string][3]string{
	"en": {"Manage the selected configuration through authenticated v2 operations.", "Request failed. Check the operation ID before retrying an uncertain write.", "Stage reads a bounded configuration request from stdin (--request-file -). Commit and rollback require confirmation within 30–120 seconds. No fallback to legacy writes."},
	"es": {"Administrar la configuración seleccionada mediante operaciones v2 autenticadas.", "La solicitud falló. Consulte el ID de operación antes de repetir una escritura incierta.", "Stage lee una solicitud limitada desde stdin (--request-file -). Commit y rollback requieren confirmación en 30–120 segundos. No se sustituyen por escrituras heredadas."},
	"pt": {"Administrar a configuração selecionada por operações v2 autenticadas.", "A solicitação falhou. Consulte o ID da operação antes de repetir uma gravação incerta.", "Stage lê uma solicitação limitada de stdin (--request-file -). Commit e rollback exigem confirmação em 30–120 segundos. Não há substituição por gravações legadas."},
}

func configurationCommand(input string) (string, bool) {
	match := ""
	for _, command := range []string{"status", "stage", "validate", "commit", "confirm", "save", "rollback", "operation", "execute", "audit", "help"} {
		if command == input {
			return command, true
		}
		if input != "" && strings.HasPrefix(command, input) {
			if match != "" {
				return "", false
			}
			match = command
		}
	}
	return match, match != ""
}

func runConfigurationV2(args []string, locale string, stdin io.Reader, stdout, stderr io.Writer) int {
	copy := configurationText[locale]
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
		fmt.Fprintln(stderr, code+":", copy[1])
		return 2
	}
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] != "" && strings.HasPrefix("help", args[0])) {
		fmt.Fprintln(stdout, copy[0])
		fmt.Fprintln(stdout, "andeiva configuration <status|stage|validate|commit|confirm|save|rollback|operation|execute|audit>")
		fmt.Fprintln(stdout, "  --url https://HOST:PORT --ca-file FILE --credentials-file FILE")
		fmt.Fprintln(stdout, "  stage --request-file - | commit [--confirm-seconds 30..120]")
		fmt.Fprintln(stdout, "  confirm --origin OPERATION --target REVISION | rollback --target REVISION [--confirm-seconds 30..120]")
		fmt.Fprintln(stdout, "  operation --operation-id ID | execute --operation-id ID")
		fmt.Fprintln(stdout, "  audit [--before SEQUENCE] [--limit 1..100]")
		fmt.Fprintln(stdout, copy[2])
		return 0
	}
	command, valid := configurationCommand(args[0])
	if !valid || command == "help" {
		return fail(nil)
	}
	options := map[string]string{}
	for i := 1; i < len(args); i += 2 {
		if i+1 >= len(args) || args[i+1] == "" {
			return fail(nil)
		}
		key := args[i]
		switch key {
		case "--url", "--ca-file", "--credentials-file", "--request-file", "--confirm-seconds", "--target", "--origin", "--operation-id", "--before", "--limit":
		default:
			return fail(nil)
		}
		if _, duplicate := options[key]; duplicate {
			return fail(nil)
		}
		options[key] = args[i+1]
	}
	if options["--url"] == "" || options["--ca-file"] == "" || options["--credentials-file"] == "" {
		return fail(nil)
	}
	for flag, allowed := range map[string]bool{
		"--request-file": command == "stage", "--confirm-seconds": command == "commit" || command == "rollback",
		"--target": command == "confirm" || command == "rollback", "--origin": command == "confirm",
		"--operation-id": command == "operation" || command == "execute",
		"--before":       command == "audit", "--limit": command == "audit",
	} {
		if options[flag] != "" && !allowed {
			return fail(nil)
		}
	}
	var before uint64
	limit := 50
	if text := options["--before"]; text != "" {
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != text {
			return fail(nil)
		}
		before = value
	}
	if text := options["--limit"]; text != "" {
		value, err := strconv.Atoi(text)
		if err != nil || value < 1 || value > 100 || strconv.Itoa(value) != text {
			return fail(nil)
		}
		limit = value
	}
	request := adminapi.OperationRequestV2{Operation: command}
	if command == "stage" {
		if options["--request-file"] != "-" || stdin == nil {
			return fail(nil)
		}
		data, err := io.ReadAll(io.LimitReader(stdin, 65537))
		if err != nil || len(data) > 65536 || firewallipc.Decode(data, &request) != nil || request.Operation != command || request.Config == nil || request.ConfirmSeconds != nil || request.Target != "" || request.Origin != "" || request.Subject != "" {
			return fail(nil)
		}
		if request.Config.Routed == nil {
			return fail(adminclient.ErrConfiguration)
		}
		network, err := networkplan.Canonical(request.Config.Routed.Network.Config)
		if err != nil {
			return fail(adminclient.ErrConfiguration)
		}
		request.Config.Routed.Network = network
		canonical, err := configpoc.CanonicalRouted(*request.Config)
		if err != nil {
			return fail(adminclient.ErrConfiguration)
		}
		request.Config = &canonical.Config
	}
	if command == "commit" || command == "rollback" {
		seconds := uint64(60)
		if value := options["--confirm-seconds"]; value != "" {
			parsed, err := strconv.ParseUint(value, 10, 64)
			if err != nil || parsed < 30 || parsed > 120 || strconv.FormatUint(parsed, 10) != value {
				return fail(nil)
			}
			seconds = parsed
		}
		value := adminapi.DecimalV2(seconds)
		request.ConfirmSeconds = &value
	}
	request.Target, request.Origin = options["--target"], options["--origin"]
	if (command == "confirm" || command == "rollback") && request.Target == "" || command == "confirm" && request.Origin == "" || (command == "operation" || command == "execute") && options["--operation-id"] == "" {
		return fail(nil)
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
	if _, err := client.Login(ctx, credentials); err != nil {
		return fail(err)
	}
	credentials = adminclient.Credentials{}
	var result any
	var operation adminapi.OperationResponseV2
	createdNamespace := ""
	if command == "audit" {
		result, err = client.ConfigurationAuditV2(ctx, before, limit)
	} else if command == "operation" {
		operation, err = client.OperationV2(ctx, options["--operation-id"])
		result = operation
	} else if command == "execute" {
		operation, err = client.ExecuteV2(ctx, options["--operation-id"])
		result = operation
	} else {
		var current adminapi.CurrentV2
		current, err = client.CurrentConfigurationV2(ctx)
		if err == nil && command == "status" {
			result = current
		} else if err == nil {
			var namespace adminapi.NamespaceResponseV2
			namespace, err = client.NamespaceV2(ctx, current.Domain)
			if err == nil {
				createdNamespace = namespace.Namespace
				operation, err = client.AdmitV2(ctx, adminapi.AdmitRequestV2{Namespace: namespace.Namespace, Expected: current.Global.Generation, Request: request})
				if err == nil {
					// Emit the durable ID before execution so an interrupted caller can query it.
					fmt.Fprintln(stderr, "ANDEIVA_OPERATION_ACCEPTED:", operation.Operation.ID)
					operation, err = client.ExecuteV2(ctx, operation.Operation.ID)
					result = operation
				}
			}
		}
	}
	if err == nil && createdNamespace != "" && operation.Operation.State == "final" {
		_, err = client.CloseNamespaceV2(ctx, createdNamespace)
	}
	logoutCtx, logoutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer logoutCancel()
	logoutErr := client.Logout(logoutCtx)
	if err != nil {
		return fail(err)
	}
	if logoutErr != nil {
		return fail(logoutErr)
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return fail(adminclient.ErrResponse)
	}
	if operation.Operation.Outcome != nil && operation.Operation.Outcome.Code != "applied" && operation.Operation.Outcome.Code != "applied_pending_confirmation" {
		return 2
	}
	if operation.Operation.State == "uncertain" {
		return 2
	}
	if command != "operation" && operation.Operation.State == "accepted" {
		return 3
	}
	return 0
}
