# Instalação offline experimental: DHCP inativo

Adiciona dez pacotes Debian exatos sobre 41 dependências já instaladas no Debian
13 amd64. Não habilita DHCP, altera interfaces/API nem comprova persistência de
concessões. Instalação nativa, interrupções, reinício e recursos estão pendentes.

Build sem root: entradas públicas exatas em `check/profile/archives.tsv`,
`supply-chain.json`, `source-map.json` e `provenance.json`. `DEB_CACHE` contém
51 DEBs para avisos; apenas dez entram no bundle. `SOURCE_CACHE` inclui
`downloads/<source>/<filename>`, `state/lists/<filename>` e keyring Debian
autenticado em `keys/debian-archive-keyring.gpg`. `BINARY_LISTS` contém InRelease
e Packages amd64 descomprimido. URLs de fontes em `source-map.json`; locais DEB
em Packages assinado. Não substituir versões nem executar apt online no aparelho.
A referência `base-files_13.8+deb13u7_amd64.deb`, SHA256
`fcd42bb5cb63f7bfc4326a92541247872206d60a192fdff65ca14eb83ed408b9`, fornece
textos comuns de licença; não é instalada. Origem pública:
`https://deb.debian.org/debian/pool/main/b/base-files/`.

Desenvolvimento requer Python 3, gpgv, dpkg-deb, Go 1.27.4 e módulos Go previamente
armazenados. O build não executa scripts dos pacotes.

```sh
python3 packaging/dhcp-server/offline/build.py \
  "$DEB_CACHE" "$SOURCE_CACHE" "$BINARY_LISTS" "$BASE_FILES_REFERENCE" "$NEW_OUTPUT"
go test -race ./packaging/dhcp-server/offline/check
go vet ./packaging/dhcp-server/offline/check
```

Verifica assinaturas InRelease, hashes de índices, arquivos/versões exatos e fontes.
Destino usa sqv e keyring Debian instalado fixo. Metadata security/updates vencida,
helpers diferentes, arquitetura estrangeira ou baseline diferente são recusados.
Trixie principal omite Valid-Until: não há garantia de atualização limitada no tempo.
Atualizar o perfil exige revisão, não desativar verificações.

ID = SHA256 do inventário `SHA256SUMS`, não assinatura do editor. Operador autorizado
deve confiar independentemente no código e ID revisados. Não há release público
assinado. Preparar bundle validado como root, sem links/ACL/escrita de terceiros,
em `/var/lib/andeiva-dhcp-bundles/ID`; binário executável.

```sh
# Root autorizado do laboratório: captura sem efeitos de instalação.
/var/lib/andeiva-dhcp-bundles/ID/bin/check capture > capture.json
sha256sum capture.json
# Apenas após revisão dos handlers/efeitos e backup externo de recuperação:
systemd-run --unit=andeiva-dhcp-offline-install.service --service-type=exec \
  --property=KillMode=control-group --property=SendSIGKILL=yes \
  --property=Delegate=no --property=RemainAfterExit=yes \
  --property=RuntimeMaxSec=720 --property=TimeoutStopSec=15 \
  /var/lib/andeiva-dhcp-bundles/ID/bin/check install ID APPROVED_CAPTURE_SHA256
```

A unidade fixa deve estar ausente antes. Verifica MainPID, invocação, cgroup e
política de término reais; recusa execução direta por shell. Reserva mínima de
512 MiB e 4096 inodes livres, não limite medido de consumo. Root verifica resultado
da invocação atual e cgroup vazio antes de recuperação/limpeza. Antes do recibo de
sucesso confirma que resta apenas o checker. Captura inclui configuração dpkg/NSS
local; repetir após mudanças no capturador.

Captura metadados/hashes de scripts/triggers, alternativas, AppArmor, aliases,
contas e dpkg; não conteúdos de contas/configuração. Hash observado não é aprovação.
Recusa policy-rc.d existente, Kea prévio, conta própria, configuração MySQL ou
servidor DHCP observado.

APT mantém locks POSIX nativos. Fontes/configuração privadas vazias e opções
`--no-download --no-remove --no-upgrade --no-install-recommends`. Hook VERSION 3
valida ações reais completas e captura sob lock: somente dez unpack/configure
novos exatos; nenhum extra, substituição, remoção ou omissão. Simulação não autoriza.

Antes de unpack: registro exclusivo fsync, originais protegidos, máscara admin
persistente e policy-rc.d própria deny101 apenas Kea. Este perfil **persistente**
substitui a proposta anterior de overlay privado; nunca troca hook alheio.
As guardas permanecem após sucesso/falha. Scripts revisados ainda alteram contas,
configuração, alternativas, AppArmor e triggers reais.

Sucesso exige pacotes exatos, versões/estados anteriores preservados, audit limpo,
links de boot desabilitados, unidade mascarada/inativa e ausência observada de
processos Kea/UDP67. Não comprova ausência transitória de AF_PACKET: teste nativo
pendente. Log principal limitado a 4 MiB; overflow falha. Só o log terminal duplicado
do APT é desabilitado; histórico/audit permanecem. Outros logs/disco/inodes/CPU/RAM pendentes.

Falha: conservar `/var/backups/andeiva-dhcp-offline`, máscara e policy. Repetição
recusa operação retida. Sem resume, limpeza automática, purge, downgrade ou remoção
de contas/bibliotecas compartilhadas. Timeout não prova drenagem dos filhos.
Revisar processos/dpkg/registros/backups antes de recuperar; nunca copiar status
antigo sobre dpkg ativo. Originais+hashes não são rollback completo do filesystem.
Upgrade e rollback de concessões persistentes exigem testes separados.

Inventário dez+41 não é SBOM completo. Avisos originais e licenças comuns Debian
preservados; conclusões legais NOASSERTION. Apache-2.0 apenas código ANDEIVA.
Inclui sete versões fonte com alterações Debian/hashes para acompanhar entregas
binárias autorizadas; não instaladas/compiladas. Disponibilidade não significa
liberação jurídica nem cumprimento completo de obrigações de redistribuição.
