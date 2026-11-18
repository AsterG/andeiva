# Laboratório nativo DHCP jobs v4

Fixture preparada; compilação e teste ignorado por opt-in não qualificam execução
nativa. Somente Debian 13 isolado: não usar WSL, CI ou appliance instalada.
Comandos de compilação, artefatos e execução estão na
[receita EN](dhcp-jobs-native-v4.en.md). Usar Go 1.27.4 e registrar SHA-256 do
binário, script e hook; diretório root 0755, sem links ou escrita por terceiros.

Dependências: dhcpcd, BusyBox com udhcpd, iproute2, nftables, nsenter, setpriv e
mount. udhcpd é apenas um servidor de pacotes de teste. O orquestrador deve
reservar a unidade ausente `andeiva-preview-grouped.service`, exigida pelo
produtor real, com cgroup root sem delegação e namespace de mounts privado.
Não substituir nem ativar uma unidade instalada. Preparar `/run/netns` e
`/usr/libexec`; o script instala o hook somente sobre tmpfs privado.

O script cria três namespaces e dois veth isolados, herda pins FD3–5 e não recebe
PID pelo ambiente. A preparação offline e metadata Schema1 são reais de
laboratório. O helper produtivo compartilha o mesmo executor LAN entre autoridade
e DHCP; mantém NET_ADMIN, API sem capacidades e FD15 privado somente no helper.

Primeiro modo: Service autenticado NoNetwork→Stage/Validate/Commit/Confirm DHCP,
inspeção completa, aquisição real, prova selected `dhcp_live`, leitura de
endereço/rota do kernel, renovação natural com novo epoch e deadline original,
reinício somente da API mantendo helper/produtor. Rollback com trabalho DHCP ativo
deve ser recusado sem alterar Running ou lease. Marcadores JSON
`ANDEIVA_NATIVE_DHCP_JOBS`: bound, renewed, restarted, rollback-fenced. Limpeza:
`ANDEIVA_NATIVE_DHCP_JOBS_CLEANUP_OK`.

Para o modo opcional `--shared-wan`, compilar o binário com a tag de diagnóstico
`andeiva_native_dhcp_diagnostics` e acrescentar essa opção ao script.
O teste reserva dois cgroups exatos, verifica que drenar a WAN cancela a
autorização de início e rejeita um segundo início com a mesma identidade.
Depois, drena o espaço LAN vazio com DHCP WAN ativo e verifica a continuidade
de TCP e UDP durante o reinício da API, mantendo o Work e a concessão. O Kea
ativo e o perfil de serviço instalado exigem qualificação nativa separada.

O primeiro modo não comprova retirada transacional/rollback para NoNetwork, módulo desativado sem
recursos, expiração, morte do proprietário, tráfego, reboot ou orçamento de
recursos. O gate residual fechado desaparece somente ao retirar o namespace
inteiro. Preservar evidências de falhas; não remover pins com identidade alterada
ou processos vivos. Ausência de resultado nunca significa sucesso.
