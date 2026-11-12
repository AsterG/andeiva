package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/adminclient"
)

var systemText = map[string][3]string{
	"en": {"Read the running appliance's product version over authenticated HTTPS.", "Request failed. Check the connection, credentials and permissions.", "--version reports this local CLI build; system info reports the connected appliance. Update availability is not implemented."},
	"es": {"Consultar la versión del appliance en ejecución mediante HTTPS autenticado.", "La solicitud falló. Revise conexión, credenciales y permisos.", "--version muestra la compilación local de la CLI; system info consulta el appliance conectado. La disponibilidad de actualizaciones no está implementada."},
	"pt": {"Consultar a versão do appliance em execução por HTTPS autenticado.", "A solicitação falhou. Verifique conexão, credenciais e permissões.", "--version mostra a compilação local da CLI; system info consulta o appliance conectado. A disponibilidade de atualizações não está implementada."},
}

func runSystem(args []string, locale string, stdout, stderr io.Writer) int {
	text := systemText[locale]
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
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] != "" && strings.HasPrefix("help", args[0])) {
		fmt.Fprintln(stdout, text[0])
		fmt.Fprintln(stdout, "andeiva [--lang en|es|pt] system info --url https://HOST:PORT --ca-file FILE --credentials-file FILE")
		fmt.Fprintln(stdout, "andeiva [--lang en|es|pt] system network-interfaces --url https://HOST:PORT --ca-file FILE --credentials-file FILE")
		fmt.Fprintln(stdout, text[2])
		return 0
	}
	operation := ""
	for _, command := range []string{"info", "network-interfaces"} {
		if args[0] != "" && strings.HasPrefix(command, args[0]) {
			if operation != "" {
				return fail(nil)
			}
			operation = command
		}
	}
	if operation == "" {
		return fail(nil)
	}
	options := map[string]string{}
	for i := 1; i < len(args); i += 2 {
		if i+1 >= len(args) || args[i+1] == "" {
			return fail(nil)
		}
		key := args[i]
		if key != "--url" && key != "--ca-file" && key != "--credentials-file" {
			return fail(nil)
		}
		if _, duplicate := options[key]; duplicate {
			return fail(nil)
		}
		options[key] = args[i+1]
	}
	if len(options) != 3 {
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err = client.Login(ctx, credentials); err != nil {
		return fail(err)
	}
	credentials = adminclient.Credentials{}
	var info any
	var readErr error
	if operation == "network-interfaces" {
		info, readErr = client.NetworkInterfacesV2(ctx)
	} else {
		info, readErr = client.SystemInfo(ctx)
	}
	// Logout has its own deadline even if the metadata request was cancelled.
	logoutCtx, logoutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer logoutCancel()
	logoutErr := client.Logout(logoutCtx)
	if readErr != nil {
		return fail(readErr)
	}
	if logoutErr != nil {
		return fail(logoutErr)
	}
	if err := json.NewEncoder(stdout).Encode(info); err != nil {
		return fail(adminclient.ErrResponse)
	}
	return 0
}
