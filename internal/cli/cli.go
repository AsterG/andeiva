// Package cli implements the local development scaffold command grammar.
package cli

import (
	"fmt"
	"io"
)

type messages struct {
	help            string
	status          string
	invalidArgument string
	invalidLocale   string
}

var translations = map[string]messages{
	"en": {
		help:            "ANDEIVA Security Gateway\nUsage: andeiva [--lang en|es|pt] [help|status]\n\nhelp    Show this help\nstatus  Show the scaffold development status\n",
		status:          "Phase 0 scaffold only. Gateway features are not implemented.",
		invalidArgument: "Unsupported arguments. Run andeiva help.",
		invalidLocale:   "Unsupported language. Choose en, es or pt.",
	},
	"es": {
		help:            "ANDEIVA Security Gateway\nUso: andeiva [--lang en|es|pt] [help|status]\n\nhelp    Mostrar esta ayuda\nstatus  Mostrar el estado de desarrollo de la estructura inicial\n",
		status:          "Solo estructura inicial de Fase 0. Las funciones del gateway no están implementadas.",
		invalidArgument: "Argumentos no admitidos. Ejecute andeiva help.",
		invalidLocale:   "Idioma no admitido. Elija en, es o pt.",
	},
	"pt": {
		help:            "ANDEIVA Security Gateway\nUso: andeiva [--lang en|es|pt] [help|status]\n\nhelp    Mostrar esta ajuda\nstatus  Mostrar o estado de desenvolvimento da estrutura inicial\n",
		status:          "Somente estrutura inicial da Fase 0. As funções do gateway não estão implementadas.",
		invalidArgument: "Argumentos não permitidos. Execute andeiva help.",
		invalidLocale:   "Idioma não permitido. Escolha en, es ou pt.",
	},
}

// Run writes a localized result and returns a process exit status.
// It performs no network, filesystem or privileged operation.
func Run(args []string, stdout, stderr io.Writer) int {
	text := translations["en"]
	if len(args) > 0 && args[0] == "--lang" {
		if len(args) < 2 {
			fmt.Fprintln(stderr, "ANDEIVA_INVALID_ARGUMENT:", text.invalidArgument)
			return 2
		}
		var ok bool
		text, ok = translations[args[1]]
		if !ok {
			fmt.Fprintln(stderr, "ANDEIVA_UNSUPPORTED_LOCALE:", translations["en"].invalidLocale)
			return 2
		}
		args = args[2:]
	}
	if len(args) == 0 || len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(stdout, text.help)
		return 0
	}
	if len(args) == 1 && args[0] == "status" {
		fmt.Fprintln(stdout, text.status)
		return 0
	}
	// Do not reflect arbitrary input into terminal output.
	fmt.Fprintln(stderr, "ANDEIVA_INVALID_ARGUMENT:", text.invalidArgument)
	return 2
}
