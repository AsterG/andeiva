# TP-DHCP-LAN-001 — Empacotamento offline do servidor DHCPv4

Responsável: backend/control plane. Data: 2026-11-13. Estado: **proposta; não
selecionado, implementado, instalado ou qualificado**. Base main `ca4afb2`;
contrato PR70 `dee8c1b` e testes de limites `06d6c67`. Nenhuma mudança de API/runtime.
[English](en.md) · [Español](es.md) · [Evidência de dependências](evidence.md).

## Decisão proposta para ADR

Avaliar `kea-dhcp4-server` do Debian13, `kea-common` com versão exata e fechamento
completo das dependências verificadas. Primeiro laboratório com memfile
persistente: sem servidor de banco, hooks comerciais, DDNS, DHCPv6, relay, HA ou
control-agent. Memfile não fica autorizado para distribuição sem durabilidade.

| Opção | Consequência |
|---|---|
| Manter somente validador PR70 | Estado atual; menor risco runtime, sem servidor funcional. |
| Componente Kea DHCPv4 | Candidato existente recomendado para avaliação; requer isolamento raw, durabilidade, licença e medições. |
| dnsmasq | Comparador de consumo existente; exige paridade, isolamento e persistência independentes. Menor consumo não é presumido. |

Aplicar processo de mudança tecnológica e ADR-033 sem HA v1. ADR WAN 050/058 não
autoriza servidor. Revisões de arquitetura, segurança, licença e desempenho antes
de ADR numerado aprovado e implementação. Preservar PR70: 32 scopes, 65.536
endereços declarados, exclusões, reservas, binding LAN selecionado e
`T1 < T2 < lease`. Recusar habilitação incompatível explicitamente, sem reduzir
silenciosamente o contrato.

## Entrada offline e instalação

A [evidência](evidence.md) verifica 51 pacotes por arquitetura, 94 arquivos distintos
amd64/arm64 contra metadata Debian assinada. Não é um sistema mínimo instalável
ou atualização ANDEIVA assinada. Pacotes Essential, systemd, AppArmor e estado
dpkg real são pré-requisitos separados. Memfile não elimina bibliotecas cliente
MariaDB/PostgreSQL; seus servidores ficam fora. Não usar metapacote `kea`,
Recommends, apt online ou substituições de versão na appliance.

Reutilizar modelo de confiança do builder/verificador offline existente, não seu
instalador específico de boot. Resolver no build contra snapshot assinado e
baseline autenticado; preservar Depends/Pre-Depends e alternativas, versões
binárias/fonte, arquitetura, tamanhos/hash, metadata, fontes, licenças e SBOM.
Manifesto vincula delta exato e hash do estado destino. Se baseline mudar,
resolver novamente. Não reduzir dependências mais novas nem atualizar libc/SSL
como efeito lateral; atualização OS é outra transação revisada.

Antes dos efeitos: assinaturas ANDEIVA confiáveis, procedência Debian, relógio,
arquitetura, espaço/inodes, backup e delta exato. Simulação somente local com
`--no-download --no-install-recommends --no-remove`; comparar todas as ações ao
manifesto. Não usar `trusted=yes`, `--allow-unauthenticated` nem desativar validade.
Simulação não comprova arquivos disponíveis: verificar hashes e executar checagem
download-only/no-download de cache antes de dpkg.

## Impedir inicialização automática

Scripts Debian revisados tentam enable/start/restart, mudam contas/permissões e
recarregam AppArmor: **policy-rc.d sozinha não basta**.

1. Serializar pacotes/transições; journal durável de delta, unidades, política,
   configuração e dados preservados. Recusar servidor/conta/unidade/dados alheios;
   não adotar nem parar serviços existentes sem autoridade específica.
2. Antes de unpack/configure, máscara persistente própria e verificada de
   `kea-dhcp4-server.service`. Preservar após reboot; futuro serviço selecionado
   pertence ao launcher ANDEIVA. Provar que unmask/enable do pacote não a remove.
3. Scripts aprovados em mount namespace privado, vista imutável de policy-rc.d
   negando ativação Kea e delegando outros pedidos à política original intacta.
   Se não preservar comportamento, recusar. Caminho ausente exige vista privada
   do diretório, não substituição temporária no host. Verificar identidade/hash
   original e mount view do pai; não depender de PATH/ambiente.
4. Revisar todos os scripts/triggers do delta: contas, ldconfig, AppArmor e
   daemon-reload são efeitos reais. Execução direta/desconhecida de daemon bloqueia
   pacote. Não desativar AppArmor nem aceitar falha do parser como sucesso.
5. Verificar máscara/enablement e ausência de processo, LFC, socket raw/packet/UDP
   e resposta DHCP antes de concluir instalação. Interrupção preserva journal e
   máscara; `apt -f install` genérico não é recuperação.

## Runtime, dados e recursos

API/CLI/web usam candidato validado, RBAC, auditoria e coordenador existente.
Running após ativação verificada e confirmação; Startup somente com Save. Não
aceitar JSON de motor, executáveis, caminhos, namespaces ou privilégios do cliente.
Leases são estado operacional, não outro banco de configuração. O administrador
funcional não recebe identidades/versões do motor nem diagnóstico privilegiado.

Identidade de serviço distinta de API/helper; namespace próprio fixado e interfaces
LAN selecionadas, nunca `*`, host ou WAN. Revisar NET_RAW/NET_BIND_SERVICE sem
concedê-las à API/helper. Kea usa sockets raw para clientes diretos e o
[manual versionado](https://kea.readthedocs.io/en/kea-2.6.3/arm/dhcp4-srv.html#interface-configuration)
avisa sobre bypass do filtro IP: INPUT não prova bloqueio DHCP. Exigir fronteira
kernel e retirada verificadas antes de respostas, troca de interface, morte e
drenagem. Allowlist não confina processo NET_RAW comprometido que abra outra
interface do mesmo namespace. Não colocá-lo junto à WAN sem fronteira revisada;
nova topologia somente LAN exige aprovação separada. Não relaxar readiness.

Disabled exige zero processo servidor/LFC, socket raw/UDP/control, timer, worker
exclusivo ou regra/config gerada ativa. Preservar dados inativos. Drenar cgroup
inteiro e verificar descritores/política; pedido stop ou `ss` UDP vazio não basta.
Não apagar auditoria central nem mudar forwarding/NAT ao desativar DHCP.

Quota/reserva dedicada inclui leases, todos os
[intermediários LFC](https://kea.readthedocs.io/en/kea-2.6.3/arm/lfc.html), crescimento
durante limpeza, configuração temporária e recuperação de upgrade. Meta preliminar
**512 MiB ativos + 512 MiB de reserva**: capacidade não comprovada. Medir maior
linha/churn/cópias e recusar habilitação se não couber; 65.536 leases exigem teste
próprio. Não truncar/rotacionar leases como logs. Logs diagnósticos separados e
limitados; auditoria protegida segue Storage Manager. Limite preventivo deve parar
alocação/renovação antes da incerteza de durabilidade; se não comprovado, bloquear
seleção. ENOSPC/inodes/corrupção não podem gerar banco vazio ou esquecer concessões.

Memfile não prova sozinho ordem ACK→persistência durável. Medir fsync, corte de
energia e retrocesso do relógio; incompatibilidade exige proposta de backend, não
garantia falsa. CPU/RSS/PSS, pico LFC, boot, escritas e desativação a zero pendentes
em 2 GiB e ambas arquiteturas. Nenhuma afirmação de desempenho.

## Upgrade, remoção e rollback

Quiesce por operação selecionada durável antes de mudar pacotes. Parar servidor e
LFC, verificar drenagem, sync e snapshot completo de leases, versões de compilador/
motor e referências de auditoria. Nunca purgar leases/audit em scripts, remove,
autoremove ou rollback. Dados ANDEIVA separados dos defaults do pacote, com
permissões/AppArmor revisados. Remover somente delta próprio sem dependentes
alheios; preservar dependências compartilhadas inativas. Reinstalação deve
encontrar dados preservados.

Rollback preserva concessões emitidas desde a configuração anterior: restaurar
snapshot antigo pode duplicar endereços. Provar leitura dos dados atuais pelo
motor anterior antes de downgrade; incompatibilidade mantém serviço desativado
com estado recuperável. Reduzir/mover scope conserva ownership até expiração
original ou release verificado, sem segundo armazenamento autoritativo. Crash
continua mesma operação/deadline. Mudanças do contrato coordenador/lease precisam
de ADR próprio.

## Testes nativos futuros — nenhum executado

IDs e matriz completa em [EN](en.md#acceptance-gates--future-native-tests-not-executed).

| ID | Caso | Resultado obrigatório |
|---|---|---|
| PKG-01 | Debian13 mínimo amd64/arm64 sem motor, egress desconectado | Delta local exato; zero processo/socket/resposta antes de enable; capturas dpkg/unidade/política/AppArmor/rede host. |
| PKG-02 | Dependência ausente/corrupta/arquitetura errada, assinatura/validade/baseline inválido | Recusar antes de unpack, zero mudanças. |
| PKG-03 | Política própria/ausente, umask restritivo, motor/unidade/dados alheios | Preservar bytes/comportamento; recusar adoção. |
| PKG-04 | Kill após máscara/unpack/configure/enable/journal, reboot | Sem início stock; continuar delta exato ou bloquear preservando journal. |
| RUN-01 | Clientes reais em dois scopes, captura WAN | DORA/renew/expiry/opções; nenhuma IP excluída/router ou colisão; reserva fora pool válida; zero resposta host/WAN. |
| RUN-02 | Disable com leases/LFC, reboot/re-enable | Zero runtime exclusivo, ownership mantido sem duplicados. |
| RUN-03 | Tráfego raw durante retirada/troca de link/morte | Fence independente interrompe respostas; filtro IP isolado não é prova. |
| DATA-01 | Quota/inodes/readonly/short write/linha corrompida/kill em cada rename LFC | Sem ACK sem ownership recuperável ou fallback vazio; audit/reservas preservados. |
| DATA-02 | Corte após ACK, relógio atrás/adiante | Sem realocação prematura; evidência durável e temporal. |
| UP-01 | Upgrade enabled/disabled/interrompido, dados incompatíveis com versão antiga | Preservar estados; rollback incompatível bloqueado, leases/audit intactos. |
| RM-01 | Remove/reinstall/dependente alheio/purge | Sem apagar dados ou pacote alheio; recusar purge. |
| RES-01 | 1/32 scopes, 1/65.536 leases, churn/flood/LFC/soak24h | Medir PSS/RSS/CPU/disco/inodes/latência e delta zero disabled; revisão antes da seleção. |

Somente laboratório autorizado com snapshot e invariantes host independentes.
Metadata WSL/contêiner não qualifica appliance runtime. Nenhuma mudança EKS/Helm.
O [copyright Debian](https://metadata.ftp-master.debian.org/changelogs/main/i/isc-kea/isc-kea_2.6.3-1%2Bdeb13u1_copyright)
inclui MPL-2.0 e avisos adicionais. Revisão completa de licenças/fontes/SBOM
pendente; disponibilidade upstream não é aprovação legal. Sem hooks premium.

## Gates de revisão independente

- Testar unmask, enable, triggers, configuração interrompida e reinício contra a máscara persistente; nenhum daemon stock deve iniciar.
- Comparar políticas AppArmor carregadas no host antes/depois, inclusive falhas. Um namespace de montagem privado não torna seus efeitos locais.
- Testar worker comprometido tentando captura/transmissão AF_PACKET fora do enlace e tráfego DHCP autorizados; exigir negação efetiva.
- Vincular cada binário distribuído à fonte exata, licença e obrigações. A licença do motor não cobre todos os artefatos transitivos.

São testes futuros obrigatórios, não evidência de instalação concluída.
### Todos os sockets declarados devem estar disponíveis

A avaliação isolada deve configurar `service-sockets-require-all: true`.
Ocupar um segundo listener LAN declarado antes da inicialização e verificar que o
servidor recusa a ativação parcial, não deixa o primeiro scope utilizável e
informa a falha. Liberar o conflito e verificar a recuperação explícita.
Um processo ativo não comprova que todas as interfaces declaradas estão atendidas.
É um critério de aceitação; ANDEIVA ainda não implementa esse ajuste do motor.
