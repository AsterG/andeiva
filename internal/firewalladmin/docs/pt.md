# Laboratório administrativo de firewall — Português

Estado: implementação experimental com validação limitada em Debian. Consulte
[resultados e limitações](../VALIDATION.md). Não é um guia de appliance de produção.

## Preparação e instalação por versão

Use uma VM Debian 13 descartável com snapshot de recuperação autorizado. O argumento
`--snapshot-confirmed` reconhece esse requisito; não cria nem verifica um snapshot
do hipervisor. Não execute o laboratório privilegiado no Windows, em appliances de
clientes ou em redes de produção compartilhadas. Go 1.27.3, as ferramentas e dependências
frontend fixadas pelo repositório, nftables 1.1.3 e os caminhos `/usr/bin/ip`,
`/usr/bin/nsenter`, `/usr/bin/setpriv`, `/usr/sbin/nft` devem estar disponíveis.
Dependências de compilação pertencem ao ambiente de desenvolvimento; este procedimento
não instala nem atualiza pacotes do appliance pela Internet.

O runtime usa UID/GID numérico **1001**, sem grupos suplementares. Reserve essa
identidade para o laboratório. O operador usa UID/GID **1000**, proprietário das
credenciais geradas. Os valores são fixos neste experimento; não são criadas contas
com nomes. Não reutilize uma identidade de serviço pertencente a outra carga.

Execute a partir de um checkout revisado dentro do laboratório. Trata-se da primeira
instalação em um novo diretório de versão, não de uma atualização automática.
Executáveis, arquivos web e diretórios superiores devem pertencer a root e não
permitir escrita por grupo ou outros. O caminho web fixo não deve existir ao criar
o link. Para trocar a versão, pare o laboratório e revise executável e destino web
juntos; os comandos não substituem um link existente.

```bash
export GOTOOLCHAIN=local GOWORK=off
ARTIFACT_VERSION="$(git rev-parse --short=12 HEAD)"
BUILD_DIR=".tmp/admin-lab-build/$ARTIFACT_VERSION"
mkdir -p "$BUILD_DIR"
go build -trimpath -o "$BUILD_DIR/andeiva-admin-lab" ./cmd/andeiva-admin-lab
go build -trimpath -o "$BUILD_DIR/andeiva" ./cmd/andeiva
npm --prefix frontend run build
INSTALL_ROOT="/opt/andeiva-admin-lab/versions/$ARTIFACT_VERSION"
sudo install -d -o root -g root -m 0755 "$INSTALL_ROOT/web"
sudo install -o root -g root -m 0755 "$BUILD_DIR/andeiva-admin-lab" "$INSTALL_ROOT/andeiva-admin-lab"
sudo install -o root -g root -m 0755 "$BUILD_DIR/andeiva" "$INSTALL_ROOT/andeiva"
sudo cp -R frontend/dist/. "$INSTALL_ROOT/web/"
sudo chown -R root:root "$INSTALL_ROOT"
sudo chmod -R go-w "$INSTALL_ROOT"
sudo ln -s "versions/$ARTIFACT_VERSION/web" /opt/andeiva-admin-lab/web
```

Não são instalados daemon, ativação no boot, regra de firewall ou forwarding do host.
Executável e compilação web devem representar a mesma revisão aprovada para teste.

## Provisionamento, TLS e acesso

```bash
LAB_DIR="$(sudo "$INSTALL_ROOT/andeiva-admin-lab" --provision)"
printf '%s\n' "$LAB_DIR"
sudo "$INSTALL_ROOT/andeiva-admin-lab" --run-lab --snapshot-confirmed "$LAB_DIR"
```

Mantenha esse terminal do supervisor aberto. Use o diretório impresso em outro
terminal; ele é gerado em `/var/tmp`, não é um caminho arbitrário de estado.
São criados `admin-a.json`, `admin-b.json` e `viewer.json`, arquivos regulares `0600`
pertencentes a 1000. Cada conta recebe uma credencial aleatória individual de 32 bytes,
codificada em 64 caracteres hexadecimais. `accounts.json` guarda os hashes. Não há
senha padrão, MFA, login de diretório nem ciclo de identidade de produção. Não publique
credenciais nem copie seus valores para comandos, logs ou evidências.

API e web escutam somente em **https://127.0.0.1:9443**, com TLS 1.3 mínimo.
Abra **https://127.0.0.1:9443/firewall** no navegador do laboratório. Inspecione
`ca.crt` e importe-o apenas em um perfil descartável de confiança do navegador antes
de conectar. Remova essa confiança ao terminar. CA e certificado do servidor expiram
em 24 horas; depois provisione outra execução descartável. Não é gravada uma chave
privada de CA. Não ignore avisos de certificado nem use opções TLS inseguras.
A origem exata é `127.0.0.1:9443`; `localhost` não passa na validação de Host.
Para um navegador fora da VM, use um túnel autorizado restrito a loopback para essa
origem exata; não exponha o listener em uma interface física.

Informe usuário e credencial do arquivo protegido no formulário web. `admin-a` e
`admin-b` podem modificar; `viewer` consulta o estado atual, mas não modifica nem
acessa o histórico. Sessões expiram após 30 minutos ou 5 minutos de inatividade.
Reiniciar a API invalida suas sessões em memória. Falhas de autenticação ou auditoria
bloqueiam operações. A interface começa em inglês e tema claro; espanhol, português
e modo escuro explícito estão disponíveis. Alterações ficam locais até Stage.
Distinga Candidate, Running, Startup e o último estado efetivo observado. A atualização
é manual.

## CLI oficial e transações

Execute a CLI como UID 1000, sem `sudo`. Substitua `<COMMIT>` e `<SUFFIX>` pela versão
instalada e pelo diretório impresso. O cliente exige uma CA explícita. O arquivo de
credenciais deve ser regular, pertencer ao usuário executante, ter um único link,
não ser link simbólico e ter modo 0600. Cada comando inicia e encerra uma sessão
sem guardar o token. Troque `--lang en` por `es` ou `pt` para localizar as mensagens.

```bash
INSTALL_ROOT="/opt/andeiva-admin-lab/versions/<COMMIT>"
LAB_DIR="/var/tmp/andeiva-admin-lab-<SUFFIX>"
fw() {
  "$INSTALL_ROOT/andeiva" --lang en firewall "$@" \
    --url https://127.0.0.1:9443 \
    --ca-file "$LAB_DIR/ca.crt" \
    --credentials-file "$LAB_DIR/admin-a.json"
}
fw status
fw list
```

Anote o hash Running inicial se desejar retornar a ele. Salve o JSON abaixo como
`stage.json` em um espaço do operador. Substitua **2** pelo valor atual exato de
`snapshot.generation` obtido com `fw status`: é um exemplo, não uma geração fixa.
Cada nova mutação precisa de outra chave de idempotência. Para repetir a mesma
solicitação, preserve a chave e todo o conteúdo original. Não repita conflitos
silenciosamente.

```json
{
  "operation": "stage",
  "key": "stage-service-01",
  "expected_generation": 2,
  "config": {
    "schema_version": 2,
    "default_action": "deny",
    "rules": [
      {
        "id": "tcp-service",
        "action": "allow",
        "match": {
          "source": "198.18.0.2/32",
          "destination": "198.18.0.6/32",
          "protocol": "tcp",
          "source_ports": {"from": 1, "to": 65535},
          "destination_ports": {"from": 18080, "to": 18080}
        }
      }
    ]
  }
}
```

```bash
fw stage --request-file stage.json
fw validate
fw commit --confirm-seconds 60
fw status
```

Antes do prazo, execute `probe tcp 18080` no supervisor e verifique `allowed`.
Confirme apenas a revisão que examinou. `fw confirm` obtém geração e hash Running
atuais e vincula a confirmação a eles; uma alteração concorrente é rejeitada.
O mesmo administrador que fez commit deve confirmar. Sem confirmação, a política
anterior é restaurada. O intervalo permitido é 30–120 segundos. `fw commit` sem
intervalo faz commit sem confirmação pendente. Nenhuma opção salva Startup.

```bash
fw confirm
fw save
fw history --limit 50
fw history --before <NEXT_BEFORE> --limit 50
fw rollback --target <EARLIER_REVISION_HASH>
fw status
```

Use a paginação somente quando `next_before` não for zero; substitua os dois marcadores
pelos valores retornados. Rollback histórico altera Running, não Startup; execute
`save` separadamente se essa revisão recuperada precisar sobreviver a um novo início
completo. Confirmação pendente bloqueia outras alterações. Outro administrador não
pode sobrescrever Candidate alheio nem confirmar seu commit. Há `help`, abreviações
inequívocas e `firewall completion`. Arquivos de solicitação podem definir geração,
chave e destino explícitos; `--request-file -` lê a entrada padrão.

O editor web usa as mesmas operações stage, validate, commit, confirm, save e
rollback histórico, com revisão da operação e da revisão de configuração. A ordem
do array define prioridade. São aceitos até 64 IDs únicos. CIDRs devem ser IPv4
canônicos; protocolo `tcp` ou `udp`; ambos os intervalos de portas são inclusivos,
não nulos e limitados a 65535. Não são aceitos shell, executável, namespace, tabela
ou programa nft arbitrários.

## Contrato HTTPS tipado

Corpos JSON têm limite de 65536 bytes. Campos desconhecidos/duplicados e valores
inválidos são rejeitados. Escritas exigem administrador, `key` e
`expected_generation`. `X-ANDEIVA-Client` aceita `web`, `cli` ou `api`: identifica
a origem da auditoria, sem conceder privilégios.

| Método e caminho | Solicitação e resposta |
|---|---|
| `POST /api/v1/auth/login` | `{username, credential}`; web recebe cookie Secure/HttpOnly/SameSite=Strict e identidade/CSRF; CLI/API recebem também token bearer |
| `GET /api/v1/auth/session` | Identidade, função, validade e CSRF atuais |
| `POST /api/v1/auth/logout` | Objeto vazio; invalida o token atual |
| `GET /api/v1/firewall` | `{snapshot, effective}`; revisões e contadores limitados `{id, packets, bytes}` |
| `POST /api/v1/firewall/transactions` | `{operation, key, expected_generation, config?, confirm_for?, target?}`; retorna estado atual |
| `GET /api/v1/firewall/history?before=0&limit=50` | Somente administrador: `{revisions, audit, next_before}`; limite 1–100 |

`config` aparece apenas em `stage`; `confirm_for` é um inteiro JSON em nanossegundos
para `commit` (60 segundos = `60000000000`); `target` contém o hash Running exato
para `confirm` ou um hash do histórico para `rollback`. As outras operações são
`validate` e `save`. Escritas web exigem Origin exata e `X-CSRF-Token`; clientes
bearer enviam `Authorization: Bearer TOKEN` sem enviar também o cookie de sessão.
Não persista tokens no armazenamento do navegador nem em argumentos de comandos.

Estados efetivos são `verified`, `pending_confirmation`, `recovery_required` ou
`unavailable`. Verificado significa correspondência semântica com Running na última
leitura, não monitoramento contínuo ou certificação. Erros retornam
`{code, request_id}`: entrada inválida 400, identidade negada 401, operação proibida
403, conflitos de geração/repetição/pendência 409 e recuperação indisponível 503.
Após resposta ambígua, atualize e revise antes de outra alteração.

## Tráfego isolado e ciclo de vida

Três namespaces sem nome contêm origem `198.18.0.2`, gateway e destino
`198.18.0.6`. Listeners de eco TCP/UDP usam 18080–18082. O gateway administra somente
`inet andeiva_admin`; `src0` e `dst0` definem a direção. Endereços, rotas, regras e
forwarding do host ficam fora da política. O supervisor compara snapshots do host
e uma tabela sentinela independente no namespace.

A primeira correspondência vence; tráfego sem regra e IPv6 são negados. Cada pacote
original exige CIDRs, protocolo, portas e interfaces completos da política atual e
conntrack original/new ou established. Solicitações aceitas recebem uma marca de
admissão. Respostas exigem a tupla atual invertida, estado established/reply e essa
marca. Não há aceitação global de established. Excluir, restringir ou colocar uma
negação antes revoga respostas correspondentes; um allow atual para a mesma tupla
permite intencionalmente uma conexão já admitida. Contadores somam pacotes/bytes
nas duas direções e são zerados na substituição da tabela. Não são logs por fluxo
nem capturas de pacotes.

Comandos pela entrada padrão do supervisor:

| Comando | Comportamento |
|---|---|
| `probe tcp 18080`, `probe udp 18080` | Teste de eco original; portas válidas 18080–18082 |
| `probe-reverse tcp 18080`, `probe-reverse udp 18080` | Teste inverso não solicitado, não uma resposta estabelecida |
| `status` | Verifica snapshot do host e sentinela |
| `kill-api` | Para API; mantém helper/política e prazo independente de confirmação |
| `restart-api` | Somente com API parada; `Boot:false` retoma Running e recupera pendências/incertezas conservadoramente |
| `kill-helper` | Injeta falha: para API e fecha todo o laboratório; espera-se um erro |
| `stop` ou EOF | Verifica host/sentinela e limpa processos/namespaces próprios |

O supervisor tem limite de 60 minutos. Use `stop` para encerramento normal;
terminação forçada não substitui limpeza verificada. `kill-helper` testa encerramento
de emergência, não continuidade do plano de dados. Executar novamente
`--run-lab --snapshot-confirmed` com o mesmo diretório representa um início completo
`Boot:true`, que seleciona Startup salvo. Journal e auditoria permanecem no disco;
preserve evidências antes de retirar a VM. Nunca apague o journal para superar uma
falha de recuperação. Examine `report-<run>.json`, log de operações e auditoria com
permissões adequadas: são evidências locais, não saída da API pública. Verifique
limpeza e invariância do host antes de declarar sucesso. Remova a confiança temporária
do navegador após encerrar.

## Validação e limites

```bash
go test -race ./internal/configpoc ./internal/firewalladmin ./internal/adminauth ./internal/adminapi ./internal/adminclient ./internal/cli ./internal/firewallipc ./internal/firewallnft ./internal/nftengine ./internal/nftpoc ./internal/nftguardian ./cmd/andeiva-admin-lab
go vet ./...
go build ./...
bash scripts/check-firewall-admin.sh
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
docker build -f frontend/Dockerfile.visual -t andeiva-design-check .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check
```

Estes são comandos reproduzíveis, não uma afirmação de execução de todos os controles.
Contêineres compilam/testam código e UI; o laboratório privilegiado não é um deployment
Docker Compose ou EKS/Helm. Nenhum manifesto de runtime ou serviço é adicionado.

Em cada execução nativa autorizada registre hash exato de fontes/artefatos, versões
Debian/nft privadamente, negação inicial, solicitação/resposta permitidas, inversa
não solicitada negada, exclusão/restrição/ordem de regras, TCP/UDP, separação
Candidate/efetivo, rollback, prazo durante perda da API, reinício API, Startup/início
completo, negação viewer, gerações antigas, expiração de sessão, fechamento por falha
do helper, invariância do host e limpeza. Meça CPU, RSS máximo, tamanho do journal
e duração real. O relatório do supervisor fornece alguns valores; sozinho não é
benchmark de capacidade. As medições são registradas separadamente, sem afirmar metas de capacidade.

As execuções comprovaram criação pela Web, revisões iguais na CLI/API, TCP/UDP
permitido e negado, rejeição de permissões, concorrência, save/rollback, expiração
sem API, limpeza após queda do helper e recuperação de Startup. A repetição final
durou 57,447 segundos, consumiu 0,041 segundos CPU do supervisor e 0,609 dos filhos;
o maior pico RSS de um filho foi 19.096 KiB. Incluem pausas, não RAM agregada nem throughput.
Após um rename ambíguo do journal, preserve evidências e reinicie explicitamente
o laboratório completo pelo Startup salvo; não se promete recuperar alterações não salvas.
Queda de energia, falha do supervisor inteiro, revogação de conexões duradouras sob
carga e MFA de produção seguem sem validação. Testes com fixtures diferem do tráfego real.

Este fluxo não implementa IDS/IPS, antivírus, WAF, inspeção TLS, filtro DNS, NAT,
VPN, AD SSO, MFA, HA ou instalador de appliance. Suas permissões nunca autorizam
tráfego de produção desconhecido a contornar identidade ou inspeção obrigatórias.
O POC anterior de catálogo fixo nftables mantém um caminho schema 1 separado.

## Registro de observações de tráfego por regra

Após definir `fw`, use `fw traffic` para amostrar contadores reais do kernel.
`fw traffic --before <NEXT_BEFORE> --stream <STREAM> --limit 50` consulta registros
anteriores sem amostragem; use somente os cursores retornados. O painel Web e
`GET /api/v1/firewall/traffic` consultam os mesmos registros com permissão de administrador.
Uma linha de base não possui delta. Os horários delimitam observações, não a chegada
individual de pacotes. Somente regras explícitas são cobertas; descartes pela política
padrão não são incluídos. O histórico mantém até 512 registros em memória e desaparece
ao reiniciar a API. O novo stream rejeita cursores anteriores e informa registros
removidos pelo limite. Não são registros de conexões. Veja [o contrato](../TRAFFIC.md).
## Marco do fluxo administrativo

O [relatório do marco](../MILESTONE.md) registra duas execuções nativas no Debian:
todas as operações transacionais por Web, CLI e API, 26 sondagens TCP/UDP,
68 registros do journal, rejeições de permissões, administradores concorrentes e
recuperação. Os registros de tráfego coincidiram entre as interfaces. As amostras
finais de RSS foram 17.376/18.096 KiB para API/helper; não são um benchmark de capacidade.

Para reproduzir a aceitação, crie regras TCP e UDP pela Web, compare-as com CLI/API
e execute Stage, Validate e Commit. Teste ambos os protocolos, amostre o tráfego e
compare os registros por stream/sequence. Repita com Deny explícito, Commit
Confirmed, Confirm, Save e Rollback histórico. Teste um usuário viewer, alterações
concorrentes, interrupção da API até o vencimento e reinício completo do laboratório
a partir de Startup salvo. Capture o estado do host antes/depois e use `stop` para
verificar a limpeza. Esses testes não garantem resistência a falhas de energia,
reinícios da VM ou autenticação de produção.
