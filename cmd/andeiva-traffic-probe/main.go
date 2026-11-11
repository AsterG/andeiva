package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/AsterG/andeiva/internal/trafficprobe"
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout)) }

func run(ctx context.Context, args []string, output io.Writer) int {
	flags := flag.NewFlagSet("andeiva-traffic-probe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	authorized := flags.Bool("authorized-lab", false, "Explicitly acknowledge the authorized laboratory scope")
	mode := flags.String("mode", "", "tcp | udp-echo | dns-a | http-head")
	source := flags.String("source-ipv4", "", "IPv4 address already assigned to this client")
	target := flags.String("target-ipv4", "", "One explicit numeric IPv4 target")
	port := flags.Uint("port", 0, "Target port 1..65535")
	timeout := flags.Duration("timeout", 3*time.Second, "Positive timeout, maximum 15s")
	query := flags.String("dns-name", "", "DNS A query; explicit server is target-ipv4:port")
	origin := flags.String("url", "", "HTTP(S) origin and path; no query, fragment or credentials")
	ca := flags.String("ca-file", "", "Optional trusted absolute regular PEM CA file for HTTPS")
	language := flags.String("lang", "en", "en | es | pt")
	invalid := trafficprobe.Result{SchemaVersion: 1, Outcome: "invalid_configuration", Transports: []trafficprobe.Transport{}}
	write := func(result trafficprobe.Result) bool { return json.NewEncoder(output).Encode(result) == nil }
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp && help[*language] != "" {
			_, err = io.WriteString(output, help[*language]+"\nandeiva-traffic-probe --authorized-lab --mode tcp|udp-echo|dns-a|http-head --source-ipv4 IP --target-ipv4 IP --port PORT [--timeout 3s] [--dns-name NAME] [--url URL] [--ca-file FILE] [--lang en|es|pt]\n")
			if err != nil {
				return 1
			}
			return 0
		}
		write(invalid)
		return 2
	}
	sourceIP, sourceErr := netip.ParseAddr(*source)
	targetIP, targetErr := netip.ParseAddr(*target)
	if sourceErr != nil || targetErr != nil || sourceIP.String() != *source || targetIP.String() != *target || *port == 0 || *port > 65535 || flags.NArg() != 0 || help[*language] == "" {
		write(invalid)
		return 2
	}
	result := trafficprobe.Run(ctx, trafficprobe.Config{AuthorizedLab: *authorized, Mode: trafficprobe.Mode(*mode), SourceIPv4: sourceIP, TargetIPv4: targetIP, TargetPort: uint16(*port), Timeout: *timeout, DNSName: *query, URL: *origin, CAFile: *ca})
	if !write(result) {
		return 1
	}
	if result.Outcome == "invalid_configuration" {
		return 2
	}
	if !result.Observed() {
		return 1
	}
	return 0
}

var help = map[string]string{
	"en": "One authorized laboratory target per invocation. Source IPv4 must be local. Timeout is not a firewall Deny verdict. HTTPS always verifies certificates; --ca-file requires an independently trusted CA file. --authorized-lab acknowledges scope and is not authentication.",
	"es": "Un destino autorizado de laboratorio por ejecución. La IPv4 de origen debe ser local. Un timeout no demuestra Deny del firewall. HTTPS siempre verifica certificados; --ca-file exige una CA de origen confiable independiente. --authorized-lab declara alcance y no es autenticación.",
	"pt": "Um destino autorizado de laboratório por execução. A IPv4 de origem deve ser local. Timeout não comprova Deny do firewall. HTTPS sempre verifica certificados; --ca-file exige uma CA de origem confiável independente. --authorized-lab declara o escopo e não é autenticação.",
}
