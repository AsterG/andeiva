# Montagem do gateway gerenciado

O launcher nativo possui um namespace novo e duas interfaces filhas privadas.
Interfaces físicas são vinculadas por índice, nome, MAC e MTU. Uma identidade
local do nó preserva as MAC filhas entre RunIDs; não é credencial nem política
compartilhada. Namespaces existentes nunca são adotados.

Somente interfaces filhas identificadas podem ser ativadas ou removidas. O
launcher não configura endereços, rotas, NAT ou encaminhamento. IPv6 e forwarding
ficam fechados antes da criação. Efeitos L3 e sua verificação continuam no motor
transacional. A API permanece no namespace de administração.

Um registro root de cutover vincula os manifestos operacionais e de interfaces.
Não substitui G1: configuração selecionada e readback independente do helper
continuam obrigatórios. O namespace só é removido após recolher os filhos do
supervisor. Arquivos desconhecidos impedem limpeza ou reinício; não são apagados.
Instalar o pacote não cria a ativação nem habilita o serviço agrupado incompleto.

Testes cobrem vínculos, hashes, substituição de interfaces, cancelamento, perda
de confirmação e limpeza idempotente. Ciclo instalado, cutover frio, bootstrap
DHCP e Internet pelo cliente exigem validações independentes.

O comando opcional de preparação root `andeiva-preview grouped-retirement-slot` pré-aloca um recibo de retirada de tamanho fixo de4096bytes. A unidade agrupada pode escrever somente esse arquivo. Antes de emiti-lo, a parada normal deve observar apenas o PID supervisor no cgroup dedicado sem delegação e então liberar o namespace próprio exato. Descendentes, timeout, arquivos desconhecidos ou limpeza incerta impedem o recibo e preservam evidências de recuperação. Não garante recuperação após SIGKILL ou falta de energia. Os testes do arquivo e da drenagem real de processos são gates separados; o consumidor não deve ser ativado antes da aprovação de ambos.

### Teste de drenagem de processos

Compile o binário de testes de `internal/previewruntime` na máquina de desenvolvimento e transfira-o com checksum SHA-256 verificado para um diretório exclusivo de root no Debian13 descartável. Não usar um appliance que já tenha `andeiva-preview-grouped.service`. O teste executa um helper fixo e um filho órfão em uma unidade transitória com rede privada. Exige o mesmo cgroup dedicado e UMask0077 do serviço proposto. Um filho vivo após Wait do helper deve impedir callback de limpeza e recibo durante cinco segundos. Antes de encerrar esse filho, são verificadas a identidade pidfd e a associação ao cgroup. Somente a drenagem observada permite callback e recibo. O callback é uma testemunha; não constitui um cutover integrado de namespaces.

Na consola root local autorizada, no diretório do binário verificado:
```bash
test "$(systemctl show andeiva-preview-grouped.service -p LoadState --value)" = not-found
systemd-run --unit=andeiva-preview-grouped --no-block --service-type=oneshot \
  --property=RemainAfterExit=yes --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=PrivateNetwork=yes \
  --property=PrivateTmp=yes --property=KillMode=control-group \
  --setenv=ANDEIVA_ROUTED_CGROUP_NATIVE=1 \
  "$PWD/routed-cgroup-native.test" \
  -test.run '^TestRoutedCgroupDrainV3Native$' -test.v -test.timeout=20s
systemctl show andeiva-preview-grouped.service -p Result -p ExecMainStatus -p InvocationID
journalctl -u andeiva-preview-grouped.service --no-pager
# After the unit has completed and the result/logs have been retained:
systemctl stop andeiva-preview-grouped.service
```
