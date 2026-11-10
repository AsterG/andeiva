# Go module attribution / Atribución / Atribuição

## English

The reviewed source dependencies `golang.org/x/crypto v0.58.0` and
`golang.org/x/sys v0.49.0` both carry Copyright 2009 The Go Authors and the
BSD-3-Clause license. Their original `LICENSE` files are identical. This directory
retains that full text as [golang-x-LICENSE.txt](golang-x-LICENSE.txt), including
the copyright, redistribution conditions, non-endorsement clause and disclaimer.
The identical upstream additional patent grant is retained separately as
[golang-x-PATENTS.txt](golang-x-PATENTS.txt). The upstream texts are unmodified;
these translations describe their packaging, not replacement license terms.

`go.mod`/`go.sum` record module requirements and checksums. This inventory does not
mean that all packages from either module are used or that both modules occur in
every binary. The Linux amd64 package dependency graph for `internal/localssh`
uses `golang.org/x/crypto` packages and does not include `golang.org/x/sys`
packages. Review the selected target, build tags, `go list -deps` output and
`go version -m` output for each shipped binary. Toolchain-vendored packages and the
Go runtime retain their separate toolchain license notice. ANDEIVA's original
code remains Apache-2.0; attribution is not a security or compliance certification.

### Packaging integration

Keep these original legal texts with source redistributions that include the
modules and with binary distributions to which their license conditions apply.
The source copies alone do not establish that a generated package contains them.
The following build integration must be checked whenever dependencies change:

| Build path | Location in the distribution |
| --- | --- |
| `packaging/preview/build.sh` | `/usr/share/doc/andeiva-firewall-preview/dependencies/golang-x-LICENSE.txt` and `golang-x-PATENTS.txt` |
| `packaging/debian/build.sh` | `/usr/share/doc/andeiva-experimental/dependencies/golang-x-LICENSE.txt` and `golang-x-PATENTS.txt`, when applicable to the packaged binaries |
| `Dockerfile` and `.dockerignore` | Make this directory available to the build and copy the legal texts into `/licenses/` for images containing applicable code |
| `.github/workflows/security.yml` | Include the legal texts alongside `LICENSE`, `NOTICE` and module inventory in the dependency artifact |

Preserve the root `NOTICE` and the existing Go runtime license. Package checks
should verify that applicable legal texts are present and byte-identical to these
source copies. Include their paths in package checksums and source-content
manifests where used. An offline build must have its reviewed dependencies already
available; this attribution does not authorize network fetching on an appliance.
This document does not claim those packaging changes have been implemented.

## Español

Las dependencias revisadas `golang.org/x/crypto v0.58.0` y
`golang.org/x/sys v0.49.0` contienen Copyright 2009 The Go Authors y licencia
BSD-3-Clause. Sus archivos `LICENSE` son idénticos; el texto completo original se
conserva en `golang-x-LICENSE.txt`. La concesión adicional de patentes, también
idéntica, se conserva en `golang-x-PATENTS.txt`. No se modificaron estos textos;
esta explicación no sustituye sus términos.

El grafo de módulos no demuestra que ambos módulos estén enlazados en cada
binario. El grafo Linux amd64 de `internal/localssh` utiliza paquetes de crypto,
sin paquetes de sys. Revise el destino, las etiquetas de compilación, `go list
-deps` y `go version -m` de cada artefacto. Conserve también `NOTICE` y la licencia
del runtime Go. El código original de ANDEIVA sigue bajo Apache-2.0; esta
atribución no certifica seguridad ni cumplimiento normativo.

Al redistribuir código sujeto a estas condiciones, incluya los textos originales
en las rutas de la tabla anterior: documentación de dependencias del paquete
Debian, `/licenses/` de la imagen aplicable y artefacto de inventario. Compruebe
presencia, igualdad de bytes y checksums. Las copias en el repositorio no prueban
su inclusión en un paquete; los ajustes de empaquetado deben validarse por
separado. No se autoriza descargar dependencias desde el appliance.

## Português

As dependências revisadas `golang.org/x/crypto v0.58.0` e
`golang.org/x/sys v0.49.0` contêm Copyright 2009 The Go Authors e licença
BSD-3-Clause. Seus arquivos `LICENSE` são idênticos; o texto original completo é
preservado em `golang-x-LICENSE.txt`. A concessão adicional de patentes, também
idêntica, é preservada em `golang-x-PATENTS.txt`. Os textos não foram modificados;
esta explicação não substitui seus termos.

O grafo de módulos não demonstra que ambos estejam vinculados a cada binário.
O grafo Linux amd64 de `internal/localssh` usa pacotes de crypto, sem pacotes de
sys. Verifique o destino, as etiquetas de compilação, `go list -deps` e
`go version -m` de cada artefato. Preserve também `NOTICE` e a licença do runtime
Go. O código original do ANDEIVA permanece sob Apache-2.0; esta atribuição não
certifica segurança nem conformidade.

Ao redistribuir código sujeito a essas condições, inclua os textos originais nos
caminhos da tabela: documentação de dependências do pacote Debian, `/licenses/`
da imagem aplicável e artefato de inventário. Verifique presença, igualdade de
bytes e checksums. As cópias no repositório não comprovam sua inclusão em um pacote;
as alterações de empacotamento exigem validação separada. Não se autoriza baixar
dependências a partir do appliance.
