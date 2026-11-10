# Serviços locais: laboratório Debian isolado

Runner experimental para uma VM Debian 13 AMD64 autorizada, com snapshot de
recuperação verificado e console disponível. Não instala serviço permanente
nem altera SSH, firewall, NAT, rotas ou interfaces físicas do host. Não executar
testes de rede privilegiados em runners compartilhados.

## Compilação e preparação

Na máquina de compilação, usar o toolchain e lockfile do repositório:

```sh
go test -race ./internal/localruntime ./internal/localadmin ./internal/localengine ./internal/localobserve
go vet ./cmd/... ./internal/...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o andeiva-local-lab ./cmd/andeiva-local-lab
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o andeiva ./cmd/andeiva
cd frontend
npm ci --ignore-scripts --no-audit --no-fund
npm run build
```

Transferir binários e `frontend/dist` por um meio autorizado e comparar SHA-256
após a transferência. O diretório dos binários deve pertencer a root, permitir
leitura à conta API e execução ao helper. Não colocá-lo no diretório privado de
estado. Nunca incluir credenciais em argumentos, logs ou artefatos públicos.

Criar duas contas de sistema dedicadas, com UID/GID não zero e distintos, shell
sem login e sem grupos suplementares. Não reutilizar contas Alpha. Preparar
`/root/lab-config.json`, pertencente a root com modo 0600:

```json
{
  "lan_address": "198.51.100.10",
  "lan_interface": "ens34",
  "allowed_cidr": "198.51.100.2/32",
  "api_user": "andeiva-local-api",
  "api_group": "andeiva-local-api",
  "helper_user": "andeiva-local-helper",
  "helper_group": "andeiva-local-helper",
  "web_root": "/opt/andeiva-local-lab/dist"
}
```

Os endereços são exemplos: substituir por valores LAN existentes e autorizados,
sem adicioná-los ao host. TCP 18443 deve estar livre no endereço selecionado e
em loopback; não há escuta global nem alternativa automática WAN. Com o binário
no PATH, executar como root dentro da VM:

```sh
andeiva-local-lab provision /var/tmp/andeiva-local-example01 /root/lab-config.json
andeiva-local-lab run --snapshot-confirmed /var/tmp/andeiva-local-example01
```

Na primeira preparação, o diretório de estado não deve existir. Repetir
`provision` valida o estado existente sem regenerar credenciais nem criar contas
OS. São gerados CA/certificado TLS de laboratório, chave SSH e credenciais de
operador independentes. Proteger `operator/{admin-a,admin-b,viewer}.json` como
root 0600. O certificado dura 24 horas; não há renovação automática aqui. Confiar
nessa CA somente em um perfil de cliente de testes descartável.

## Administração e confirmação

Abrir `https://<endereço-LAN-autorizado>:18443/local-services` e entrar com a conta
provisionada. Light é o padrão; Dark é opcional. O endereço fixo de recuperação
não pode ser editado nessa tela.

Habilitar HTTPS ou SSH, selecionar interface/endereço do inventário isolado,
porta TCP acima de 1023 e CIDRs de origem explícitos. Preparar Candidate, validar
e aplicar Commit com prazo de confirmação. Save grava Running em Startup;
confirmar não executa Save implicitamente.

Confirm exige provas autenticadas em cada binding habilitado. Usar `probe`,
descrito no README superior, com generation, target e lease da transação pendente
e o mesmo administrador. HTTPS verifica a CA e SSH a chave exata do servidor.
Arquivos de prova são privados e expiram. Inserir tokens na confirmação antes
do prazo; não capturar nem registrar o formulário com tokens. Desabilitar todos
os serviços administrados exige somente a prova de recuperação obtida pela UI.

```sh
andeiva local-services --help
andeiva local-services status --url https://127.0.0.1:18443 \
  --ca-file /var/tmp/andeiva-local-example01/ca.crt \
  --credentials-file /var/tmp/andeiva-local-example01/operator/admin-a.json
```

Web, CLI e API compartilham `/api/v1/local-services`, suas rotas de transações e
histórico e `/api/v1/effective-policies`. Usar geração e chaves de pedido estáveis.
Após resposta incerta, consultar estado antes de criar outra operação. Viewer
pode ler estado/regras efetivas, mas não escrever nem consultar auditoria. Regras
geradas são consultáveis, sem edição direta em Políticas efetivas.

## Falhas e limpeza

Em outro console root autorizado:

```sh
andeiva-local-lab check /var/tmp/andeiva-local-example01
andeiva-local-lab fault /var/tmp/andeiva-local-example01 api-kill
andeiva-local-lab check /var/tmp/andeiva-local-example01
andeiva-local-lab stop /var/tmp/andeiva-local-example01
```

Testar também `helper-kill` e mudança pendente com `api-pause`. Registrar run,
instance, gerações e hashes antes/depois; verificar tráfego real após recuperação,
não apenas respostas API. Reset recria a fixture e interrompe o serviço: não
demonstra continuidade. Limite: três resets e 128 probes por supervisor.
Reiniciar o supervisor preserva journal; não apagar estado para ocultar falhas.

No mesmo boot OS, Running confirmado é preservado, mesmo sem Save. Novo boot OS
carrega Startup. Metadados de boot ausentes/inválidos com journal bloqueiam início.
Revisão não confirmada deve restaurar sua predecessora verificada. Verificar
listeners, regras, auditoria e tráfego IPv4/IPv6 autorizado e negado; distinguir
timeout de recusa TCP e erros TLS, chave ou autenticação.

Stop libera somente processos, namespaces e sockets próprios. Comparar regras,
interfaces e rotas do host com a base e verificar serviços instalados. Conservar
estado/evidência protegidos até revisar resultados. Remover somente diretórios e
contas criados para este teste, sem processos que os utilizem. Nunca limpar o
ruleset do host nem apagar recursos de outros experimentos.
