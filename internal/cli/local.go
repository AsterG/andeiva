package cli

import (
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
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localadmin"
)

var localCommands = []string{"list", "status", "stage", "validate", "commit", "confirm", "save", "rollback", "history", "proof", "effective", "help"}
var localText = map[string][3]string{
	"en": {"Authenticated local service management. Use the recovery endpoint for activation.", "Request rejected. Check access, revision and required endpoint proofs.", "Commit and rollback require confirmation. Confirm needs a request file containing proofs from every enabled endpoint. Proof tokens are short-lived and are not saved by this command."},
	"es": {"Administración autenticada de servicios locales. Use el punto de recuperación para aplicar cambios.", "Solicitud rechazada. Revise el acceso, la revisión y las pruebas de conectividad requeridas.", "Commit y rollback requieren confirmación. Confirm necesita un archivo de solicitud con pruebas de cada punto habilitado. Los tokens caducan y este comando no los guarda."},
	"pt": {"Administração autenticada de serviços locais. Use o ponto de recuperação para aplicar alterações.", "Solicitação rejeitada. Verifique acesso, revisão e provas de conectividade exigidas.", "Commit e rollback exigem confirmação. Confirm precisa de um arquivo de solicitação com provas de cada ponto habilitado. Os tokens expiram e este comando não os salva."},
}

func localCommand(input string) (string, bool) {
	for _, c := range localCommands {
		if c == input {
			return c, true
		}
	}
	found := ""
	for _, c := range localCommands {
		if input != "" && strings.HasPrefix(c, input) {
			if found != "" {
				return "", false
			}
			found = c
		}
	}
	return found, found != ""
}

func localOptions(args []string) (map[string]string, error) {
	values := map[string]string{}
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) || args[i+1] == "" {
			return nil, adminclient.ErrConfiguration
		}
		key := args[i]
		switch key {
		case "--url", "--ca-file", "--credentials-file", "--request-file", "--confirm-seconds", "--target", "--before", "--limit", "--service", "--interface", "--protocol", "--port", "--source":
		default:
			return nil, adminclient.ErrConfiguration
		}
		if _, exists := values[key]; exists {
			return nil, adminclient.ErrConfiguration
		}
		values[key] = args[i+1]
	}
	return values, nil
}

func localRequestFile(path string, stdin io.Reader, out any) error {
	r := stdin
	if path != "-" {
		// #nosec G304 -- Explicit local CLI input path; regular file and 64 KiB read bound, never a server-side path.
		f, err := os.Open(path)
		if err != nil {
			return adminclient.ErrConfiguration
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			return adminclient.ErrConfiguration
		}
		r = f
	}
	if r == nil {
		return adminclient.ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(r, firewallipc.MaxFrame+1))
	if err != nil || len(data) > firewallipc.MaxFrame || firewallipc.Decode(data, out) != nil {
		return adminclient.ErrConfiguration
	}
	return nil
}

func runLocalServices(args []string, locale string, stdin io.Reader, stdout, stderr io.Writer) int {
	copy := localText[locale]
	fail := func(err error) int {
		code := "ANDEIVA_INVALID_ARGUMENT"
		var api *adminclient.APIError
		if errors.As(err, &api) {
			code = api.Code
		}
		fmt.Fprintln(stderr, code+":", copy[1])
		return 2
	}
	if len(args) == 0 {
		args = []string{"help"}
	}
	command, ok := localCommand(args[0])
	if !ok {
		return fail(nil)
	}
	if command == "help" && len(args) == 1 {
		fmt.Fprintln(stdout, copy[0])
		fmt.Fprintln(stdout, "andeiva [--lang en|es|pt] local-services <list|status|stage|validate|commit|confirm|save|rollback|history|proof>")
		fmt.Fprintln(stdout, "  --url https://HOST:PORT --ca-file FILE --credentials-file FILE")
		fmt.Fprintln(stdout, "  stage|proof --request-file FILE|-; confirm [--request-file FILE|-]")
		fmt.Fprintln(stdout, "  commit [--confirm-seconds 30..120]; rollback --target REVISION [--confirm-seconds 30..120]")
		fmt.Fprintln(stdout, "  history [--before SEQUENCE] [--limit 1..100]")
		fmt.Fprintln(stdout, "andeiva effective-policies --url https://HOST:PORT --ca-file FILE --credentials-file FILE [--service ID] [--interface NAME] [--protocol tcp|udp] [--port PORT] [--source CIDR]")
		fmt.Fprintln(stdout, copy[2])
		return 0
	}
	v, err := localOptions(args[1:])
	if err != nil || command == "help" {
		return fail(err)
	}
	for _, key := range []string{"--url", "--ca-file", "--credentials-file"} {
		if v[key] == "" {
			return fail(nil)
		}
	}
	for key := range v {
		switch key {
		case "--url", "--ca-file", "--credentials-file":
		case "--service", "--interface", "--protocol", "--port", "--source":
			if command != "effective" {
				return fail(nil)
			}
		case "--before", "--limit":
			if command != "history" {
				return fail(nil)
			}
		case "--confirm-seconds":
			if command != "commit" && command != "rollback" {
				return fail(nil)
			}
		case "--target":
			if command != "rollback" && command != "confirm" {
				return fail(nil)
			}
		case "--request-file":
			if command == "list" || command == "status" || command == "history" || command == "effective" {
				return fail(nil)
			}
		}
	}
	var request localadmin.Request
	var proofRequest localadmin.ProofRequest
	if v["--request-file"] != "" {
		var out any = &request
		if command == "proof" {
			out = &proofRequest
		}
		if err = localRequestFile(v["--request-file"], stdin, out); err != nil {
			return fail(err)
		}
	} else if command == "stage" || command == "proof" {
		return fail(nil)
	}
	if request.Transaction.Operation != "" && request.Transaction.Operation != command {
		return fail(nil)
	}
	ca, err := adminclient.ReadCA(v["--ca-file"])
	if err != nil {
		return fail(err)
	}
	credentials, err := adminclient.ReadCredentials(v["--credentials-file"])
	if err != nil {
		return fail(err)
	}
	client, err := adminclient.New(v["--url"], ca)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err = client.Login(ctx, credentials); err != nil {
		return fail(err)
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = client.Logout(stop)
	}()
	var result any
	switch command {
	case "list", "status":
		result, err = client.LocalState(ctx)
	case "proof":
		result, err = client.LocalProof(ctx, proofRequest)
	case "history":
		before := uint64(0)
		limit := 50
		if v["--before"] != "" {
			before, err = strconv.ParseUint(v["--before"], 10, 64)
			if err != nil {
				return fail(err)
			}
		}
		if v["--limit"] != "" {
			limit, err = strconv.Atoi(v["--limit"])
			if err != nil {
				return fail(err)
			}
		}
		result, err = client.LocalHistory(ctx, before, limit)
	case "effective":
		f := localadmin.Filter{Service: v["--service"], Interface: v["--interface"], Protocol: v["--protocol"], Source: v["--source"]}
		if v["--port"] != "" {
			n, e := strconv.ParseUint(v["--port"], 10, 16)
			if e != nil || n == 0 {
				return fail(e)
			}
			f.Port = uint16(n)
		}
		result, err = client.EffectivePolicies(ctx, f)
	default:
		state, e := client.LocalState(ctx)
		if e != nil {
			return fail(e)
		}
		r := &request.Transaction
		r.Operation = command
		if r.Key == "" {
			var key [16]byte
			if _, e = rand.Read(key[:]); e != nil {
				return fail(e)
			}
			r.Key = hex.EncodeToString(key[:])
		}
		if r.ExpectedGeneration == 0 {
			r.ExpectedGeneration = state.Snapshot.Generation
		}
		if v["--target"] != "" {
			if r.Target != "" {
				return fail(nil)
			}
			r.Target = v["--target"]
		}
		if command == "commit" || command == "rollback" {
			if v["--confirm-seconds"] != "" {
				seconds, e := strconv.Atoi(v["--confirm-seconds"])
				if e != nil || seconds < 30 || seconds > 120 || r.ConfirmFor != 0 {
					return fail(e)
				}
				r.ConfirmFor = time.Duration(seconds) * time.Second
			}
			if r.ConfirmFor == 0 {
				r.ConfirmFor = 60 * time.Second
			}
		}
		if command == "commit" || command == "rollback" || command == "confirm" || command == "save" {
			caps, e := client.Capabilities(ctx)
			if e != nil || !caps.RecoveryEndpoint {
				return fail(e)
			}
			target, lease := state.Snapshot.Running.Hash, r.Key
			switch command {
			case "commit":
				if state.Snapshot.Candidate == nil {
					return fail(nil)
				}
				target = state.Snapshot.Candidate.Revision.Hash
			case "rollback":
				target = r.Target
			case "confirm":
				if state.Snapshot.Pending == nil {
					return fail(nil)
				}
				lease = state.Snapshot.Pending.Lease
				if r.Target == "" {
					r.Target = target
				}
			}
			proof, e := client.LocalProof(ctx, localadmin.ProofRequest{Generation: r.ExpectedGeneration, Target: target, Lease: lease})
			if e != nil {
				return fail(e)
			}
			request.RecoveryProof = proof.Token
		}
		result, err = client.LocalExecute(ctx, request)
	}
	if err != nil {
		return fail(err)
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return 2
	}
	return 0
}
