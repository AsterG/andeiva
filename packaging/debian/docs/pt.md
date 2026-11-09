# Pacote experimental para Debian

[English](en.md) · [Español](es.md)

Este procedimento abrange `andeiva-experimental` versão `0.0.0~exp1` em uma VM de
desenvolvimento Debian 13 amd64. O pacote contém a CLI informativa e o servidor de
verificação de saúde. Não instala firewall, autenticação, VPN, inspeção de tráfego,
agente privilegiado de administração, atualizações `.sgu` assinadas nem recuperação
A/B. O frontend continua como página de desenvolvimento separada; este serviço
não oferece administração web.

Os comandos descrevem o contrato do pacote. Uma execução bem-sucedida no laboratório
deve ser registrada para a compilação exata; este guia não afirma que os testes passaram.

## Requisitos e funções

Compile como usuário comum em uma estação Linux confiável com a revisão do código,
Bash, Git, Go 1.27.3, `dpkg-deb`, `sha256sum` e utilitários de compilação já disponíveis.
Não é necessário Docker no runtime. Um requisito ausente impede a execução; não
faça a VM baixar dependências automaticamente.

A VM já deve ter systemd como gerenciador do sistema em execução, as dependências
`systemd (>= 257)` e `init-system-helpers (>= 1.69~)`, Bash, `dpkg`, `sha256sum`,
`ps` e `ss`. A sonda de saúde não precisa de curl nem Python.

Instalação, controle do serviço e remoção exigem um console root expressamente
autorizado na VM Debian 13 isolada. Confirme sua identidade, snapshot e console de
recuperação antes das alterações. Estas etapas não se aplicam ao host Windows nem
a um gateway em operação. Não inclua credenciais em comandos, arquivos ou logs
compartilhados.

O mínimo previsto do appliance é 2 GB de RAM e 64 GB de capacidade de disco. Este
pacote não certifica esse perfil nem um instalador do appliance. Registre RAM,
espaço livre e armazenamento reais separadamente; capacidade não é espaço livre.

## Compilar e transferir

Na raiz do código confiável, com um usuário diferente de root:

```bash
set -euo pipefail
umask 077
test "$(id -u)" -ne 0
export GOENV=off GOTOOLCHAIN=local GOPROXY=off GOTELEMETRY=off
test "$(go env GOVERSION)" = go1.27.3
out_dir=$(mktemp -d "${TMPDIR:-/tmp}/andeiva-debian-package.XXXXXX")
bash packaging/debian/build.sh '0.0.0~exp1' "$out_dir"
cd -- "$out_dir"
sha256sum --check --strict SHA256SUMS
sha256sum SHA256SUMS
```

No WSL, `OUT_DIR` deve ficar no filesystem Linux, não em `/mnt/c` ou em outro
diretório montado do Windows. Os arquivos de controle do pacote exigem permissões
Unix reais; DrvFS pode informar modo `777` para o diretório e fazer `dpkg-deb`
rejeitar a compilação. Mantenha `TMPDIR` no Linux ou não o defina. Se a compilação
abortar, não considere o diretório um artefato concluído nem relaxe as verificações
de permissões.

As saídas são `andeiva-experimental_0.0.0~exp1_amd64.deb`, `SHA256SUMS` e
`build-info.txt`. O construtor aceita um terceiro argumento opcional
`SOURCE_DATE_EPOCH` ou a variável de ambiente com esse nome; caso contrário, usa
a data do commit de origem. Preserve a revisão e as informações da compilação.
Para outra versão experimental, use a mesma interface com uma versão escolhida
explicitamente, como `0.0.0~exp2`, e um novo diretório de saída.

Transfira toda a saída por transferência SSH autorizada, mídia local ou pasta
compartilhada já aprovada. Verifique a identidade do host SSH por um canal confiável;
nunca desative essa verificação. Não habilite novos serviços de compartilhamento,
SSH root, encaminhamento de portas nem alterações de rede do host ou da VPN para
este procedimento.

Registre o SHA-256 de `SHA256SUMS` por um canal independente confiável. Na VM, no
diretório transferido, compare esse valor antes de verificar o pacote:

```bash
sha256sum SHA256SUMS
sha256sum --check --strict SHA256SUMS
```

Um checksum detecta bytes alterados; não autentica o publicador quando checksum e
pacote vêm da mesma fonte não confiável. Estes são artefatos experimentais compilados
localmente, não releases assinadas. Pare se não for possível estabelecer confiança
ou integridade. Preserve o pacote verificado para os testes de remoção e reinstalação.

## Instalar na VM

Abra o console root autorizado na VM e entre no diretório do bundle verificado.
Confira o sistema e os metadados: Debian 13, `amd64`, pacote
`andeiva-experimental`, versão `0.0.0~exp1`.

```bash
set -euo pipefail
umask 077
test "$(id -u)" -eq 0
cat /etc/os-release
test "$(dpkg --print-architecture)" = amd64
package_file="$PWD/andeiva-experimental_0.0.0~exp1_amd64.deb"
test -f "$package_file"
dpkg-deb --field "$package_file" Package Version Architecture
dpkg --install "$package_file"
dpkg-query --show --showformat='${Package} ${Version} ${Status}\n' andeiva-experimental
```

O pacote instala `/usr/bin/andeiva`, `/usr/lib/andeiva/andeiva-api`,
`andeiva-api.service` e o conffile `/etc/andeiva/andeiva-api.env`. O serviço usa uma
identidade dinâmica sem privilégios e `/run/andeiva-api` para arquivos de execução;
esse diretório não armazena dados persistentes da aplicação. O helper de prontidão
limitado fica em `/usr/lib/andeiva/wait-ready`; licenças e informações da compilação
ficam em `/usr/share/doc/andeiva-experimental`.

A configuração inicial solicita habilitação e início do serviço. A política de
serviços do Debian, uma unidade desabilitada pelo operador ou uma máscara podem
adiar o início. A conclusão de `dpkg` não prova que o serviço está ativo. Confira
política e estado; se a ativação não estiver autorizada, pare sem contornar a restrição.

## Configuração, saúde e controle do serviço

O conffile padrão contém `ANDEIVA_LISTEN_ADDR=127.0.0.1:4000`. Mantenha o serviço
sem autenticação em loopback. Não o exponha por endereço LAN, escuta wildcard ou
proxy reverso. Se um teste autorizado mudar a porta, escolha um endereço loopback
numérico desocupado e ajuste todas as sondas abaixo. Não execute o conffile como
script de shell. Reinicie o serviço após uma edição aprovada.

```bash
cat /etc/andeiva/andeiva-api.env
systemctl is-enabled andeiva-api.service
systemctl is-active andeiva-api.service
andeiva help
andeiva --lang en status
andeiva --lang es status
andeiva --lang pt status
probe_addr=127.0.0.1:4000
ANDEIVA_LISTEN_ADDR="$probe_addr" /usr/lib/andeiva/andeiva-api --healthcheck
```

A sonda termina com código 0 e sem saída ao receber a resposta de saúde exata;
não usa proxies configurados. O endpoint retorna `{"status":"ok"}` somente para
indicar que o processo responde.
A CLI informa expressamente que as funções do gateway não estão implementadas.
Um comando desconhecido, como `andeiva config`, termina com código 2; ele não
configura um gateway.

Use estas operações somente na VM identificada:

```bash
systemctl stop andeiva-api.service
systemctl start andeiva-api.service
systemctl restart andeiva-api.service
systemctl status --no-pager andeiva-api.service
journalctl --unit andeiva-api.service --boot --no-pager
```

`stop` afeta a execução atual, não a habilitação no boot. Para mantê-lo parado após
reinicializações, use `systemctl disable --now andeiva-api.service`. Para restaurar
o início quando autorizado, use `systemctl enable --now andeiva-api.service`. Uma
máscara deliberada exige revisão do responsável; a instalação não deve removê-la
silenciosamente.

## Atualização e reversão explícita

Antes de atualizar, preserve o `.deb` anterior verificado, seu manifesto e uma
cópia do conffile em um diretório persistente de backup aprovado pelo operador.
Não armazene recuperação em `/run`. Atribua a `next_deb` o caminho absoluto do novo
pacote após verificar seu próprio manifesto de checksums confiável. Confira nome,
arquitetura e versão desejada antes de instalar:

```bash
test -f "$next_deb"
dpkg-deb --field "$next_deb" Package Version Architecture
dpkg --install "$next_deb"
dpkg-query --show --showformat='${Version}\n' andeiva-experimental
```

O arquivo de ambiente é um conffile do Debian. Revise qualquer pergunta sobre
substituição, sem forçá-la; preserve a configuração local loopback desejada.
Atualizações respeitam desabilitação, máscara e política local do serviço. Se
estava ativo, confira depois reinício, saúde e configuração. Se estava desabilitado
ou mascarado, confirme que o pacote não o ativou inesperadamente.

A reversão é um downgrade explícito do pacote, não uma recuperação atômica do
sistema. Atribua a `rollback_deb` o caminho absoluto do pacote anterior confiável e
verifique seu manifesto novamente. Confirme a compatibilidade do formato de
configuração e então execute:

```bash
test -f "$rollback_deb"
dpkg-deb --field "$rollback_deb" Package Version Architecture
dpkg --install "$rollback_deb"
dpkg-query --show --showformat='${Version}\n' andeiva-experimental
```

Repita as verificações de saúde e estado. Se um script do pacote falhar ou a
configuração for incompatível, pare, preserve o diagnóstico e use o plano aprovado
de recuperação da VM. Este pacote não oferece migrações de banco, partições de
rollback nem uma cadeia de atualizações offline assinadas.

## Remover, reinstalar e purgar

A remoção para o serviço e retira os executáveis do pacote, preservando o conffile.
Verifique essa preservação; não apague configurações alheias nem dados do usuário:

```bash
dpkg --remove andeiva-experimental
test -f /etc/andeiva/andeiva-api.env
test ! -e /usr/bin/andeiva
test ! -e /usr/lib/andeiva/andeiva-api
```

Para reinstalar, verifique novamente pacote e manifesto, execute
`dpkg --install "$package_file"` e repita as verificações de serviço, conffile e
saúde. Revise a configuração preservada; não suponha que contém os valores padrão.

Purgar é uma escolha explícita separada que remove o conffile do pacote:

```bash
dpkg --purge andeiva-experimental
test ! -e /etc/andeiva/andeiva-api.env
```

A purga não é uma restauração de fábrica. Não apaga backups do operador, arquivos
alheios do usuário nem o histórico do journal do sistema. Não exige limpeza recursiva.

## Verificação após reinicialização e observação de recursos

Após instalar com autorização, registre habilitação, escuta efetiva, hash da
configuração e uma amostra do processo:

```bash
systemctl is-enabled andeiva-api.service
systemctl is-active andeiva-api.service
sha256sum /etc/andeiva/andeiva-api.env
systemctl show andeiva-api.service --property=MainPID,DynamicUser,RuntimeDirectory,MemoryCurrent,CPUUsageNSec
api_pid=$(systemctl show andeiva-api.service --property=MainPID --value)
test "$api_pid" -gt 0
ps -p "$api_pid" -o pid=,uid=,rss=,pcpu=,etime=
ss -ltnp
```

Se a contabilização não estiver disponível, registre-a como indisponível. Estas
amostras não são benchmarks de throughput, capacidade ou repouso prolongado.
Preserve os resultados de forma privada e remova dados de processos ou endereços
alheios antes de compartilhá-los.

Somente com aprovação explícita para reiniciar esta VM e um snapshot de recuperação
verificado, execute `systemctl reboot` em seu console. Retorne pelo console
aprovado, repita as verificações de estado/hash/saúde e confirme que a escuta
continua em loopback. O diretório runtime pode ser recriado e o UID dinâmico mudar;
nenhum deles é identidade persistente. Registre o resultado real após o boot;
um link de habilitação não comprova que o serviço iniciou corretamente.

Se faltarem dependências, transferência, recuperação por console ou autorização,
deixe o procedimento pendente. Em falhas de escuta, início ou saúde, examine o
journal deste serviço sem ampliar exposição nem desativar proteções. Registre
revisão exata, hashes, operações, códigos de saída e limitações. Este teste não
valida capacidades de segurança do appliance nem conclui a fase do projeto.

`ANDEIVA_SERVICE_IDENTITY_CONFLICT` ou `ANDEIVA_INSTALL_PATH_CONFLICT` indicam
conflito com uma conta, grupo ou caminho existente. Preserve-os e revise a propriedade;
não apague arquivos ou contas alheios para fazer a instalação funcionar.
`ANDEIVA_SERVICE_DEFERRED` exige revisar a política e o estado real do serviço.

## Testes reproduzíveis do pacote

Execute as verificações do arquivo na estação Linux confiável, a partir da raiz
do código. Elas exigem Python 3 nessa estação, não na VM. Atribua a `exp1_deb` e
`exp2_deb` os caminhos absolutos dos pacotes verificados `0.0.0~exp1` e `0.0.0~exp2`.
Os diretórios de resultados devem ser novos e ficar fora da árvore do código:

```bash
checks_dir=$(mktemp -d "${TMPDIR:-/tmp}/andeiva-package-checks.XXXXXX")
bash packaging/debian/tests/static-package.sh --package "$exp1_deb" --evidence-dir "$checks_dir/exp1"
bash packaging/debian/tests/static-package.sh --package "$exp2_deb" --evidence-dir "$checks_dir/exp2"
sha256sum -- "$exp1_deb" "$exp2_deb"
```

A suíte de ciclo de vida é uma alternativa à instalação manual anterior: exige
uma VM VMware Debian 13 amd64 isolada, sem registro anterior do pacote, unidade,
caminhos do pacote ou política de início de serviços, e com as portas 4000 e 44001
livres. Ela rejeita estado existente; nunca apague dados ou políticas alheios para
passar no preflight. Autorização root e snapshot de recuperação confirmado são
obrigatórios.

Na VM, atribua a `exp1_deb` e `exp2_deb` os caminhos dos pacotes transferidos, a
`exp1_sha256` e `exp2_sha256` os hashes registrados pela estação confiável e a
`snapshot_ref` a referência real do snapshot confirmado. Use um diretório pai
existente pertencente a root para novos resultados. Na raiz confiável do código
dos testes:

```bash
run_evidence="/var/tmp/andeiva-native-run-$(date -u +%Y%m%dT%H%M%SZ)"
bash packaging/debian/tests/vm-lifecycle.sh run \
  --install-deb "$exp1_deb" --install-sha256 "$exp1_sha256" \
  --upgrade-deb "$exp2_deb" --upgrade-sha256 "$exp2_sha256" \
  --evidence-dir "$run_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
```

A suíte instala, altera seu próprio conffile, atualiza, faz downgrade explícito,
confere estado desabilitado/mascarado, termina deliberadamente o processo do serviço,
testa configuração inválida e recuperação, e remove, purga e reinstala seu pacote
de teste. Uma execução correta termina com esse pacote purgado. Em falha, para o
serviço próprio e preserva estado para diagnóstico. Não reinicia a VM, altera redes,
instala dependências nem opera snapshots. Nenhum resultado é presumido aqui.

A verificação do reboot real é separada e também começa em uma VM limpa autorizada:

```bash
reboot_evidence="/var/tmp/andeiva-native-reboot-$(date -u +%Y%m%dT%H%M%SZ)"
bash packaging/debian/tests/vm-lifecycle.sh prepare-reboot \
  --install-deb "$exp1_deb" --install-sha256 "$exp1_sha256" \
  --evidence-dir "$reboot_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
```

Registre o caminho dos resultados e a referência do snapshot. A preparação deixa
o pacote instalado; não comprova o resultado após o boot. Realize a reinicialização
da VM autorizada separadamente pelo console. Ao retornar, restaure
`reboot_evidence` e `snapshot_ref` com os valores registrados e volte à raiz do
código dos testes:

```bash
bash packaging/debian/tests/vm-lifecycle.sh verify-after-reboot \
  --evidence-dir "$reboot_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
bash packaging/debian/tests/vm-lifecycle.sh cleanup-reboot \
  --evidence-dir "$reboot_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
```

A verificação exige um boot ID realmente diferente e arquivos próprios inalterados;
a limpeza remove o pacote de teste. Mantenha resultados privados e preserve falhas.
Se uma verificação rejeitar propriedade ou estado, revise sem contorná-la.
