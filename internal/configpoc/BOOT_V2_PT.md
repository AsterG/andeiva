# Recuperação Startup v2 preparada

[English](BOOT_V2.md) · [Español](BOOT_V2_ES.md)

Este caminho interno está inativo. Serviços de produção, API, CLI, marcadores de
inicialização e IPC privilegiado não o habilitam. Exige configuração v2 já
inicializada, sem contornar a verificação efetiva da migração.

Um UUID de inicialização validado, fornecido pelo componente confiável,
distingue inicialização do sistema de reinício do processo. O reinício mantém
Running e resolve operações interrompidas ou não confirmadas pela operação e
lease originais. Uma nova inicialização seleciona o conteúdo salvo em Startup
somente após validar e verificar todos os componentes. Startup permanece igual;
as gerações global e de domínio avançam. Candidate conserva proprietário, base
e revisão, sem aplicação ou atualização implícita da base. Uma base desatualizada
exige preparar novamente as alterações antes do Commit.

Antes dos efeitos são persistidos intent, margem contábil limitada e o recurso
obrigatório permanente `boot_startup.v1`. Não há usuário, recibo de admissão ou
origem de confirmação fabricados. Running, auditoria e referência validada da
inicialização concluída são selecionados juntos. Reabrir a mesma inicialização
verifica o estado efetivo sem repetir efeitos ou publicação, inclusive após
falha anterior ao marcador externo. Leitores antigos estritos rejeitam o recurso,
que persiste após checkpoints. Campos opcionais nulos preservam os bytes e hashes
anteriores.

O adaptador preparado usa o bootstrap único do guardian; Apply normal exige
lease exata. Rejeita leases alheias e verifica o estado após respostas perdidas.
O callback tipado de recuperação delimitada ainda não possui binding IPC
privilegiado. Uma inicialização parcial conserva o Running anteriormente
selecionado e exige o mesmo contexto para retomada, sem inventar revisão
verificada. Não realizar downgrade nem remover um recurso obrigatório selecionado.

**Local Services com Running diferente de Startup é rejeitado antes dos efeitos.**
O mapper de listeners e evidências continua pendente F. Nenhum domínio é omitido.
Não ativar antes de qualificar montagem do runtime, helper autenticado,
recuperação de serviços locais e inicialização real do sistema.

## Reprodução

Com Go 1.27.4 no Linux, a partir da raiz:

```sh
go test -race ./internal/configpoc ./internal/firewalladmin -run '^(TestV2Boot|TestPreparedStartup)' -count=1 -timeout=5m
go test -race ./internal/configpoc ./internal/firewalladmin ./internal/nftguardian -count=1 -timeout=10m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

Os testes usam journals temporários reais, motores simulados e guardian no mesmo
processo. Saídas de processos filhos verificam interrupções em intent, efeitos,
leitura e seleção. Cobrem repetição, confirmação pendente, Candidate inativo,
UUID/registros inválidos, referência ausente, orçamento lógico e rejeição de
leitores antigos após 64 seleções. Não testam nftables, listeners, IPC, reboot,
falta de energia ou reserva física. Não exigem privilégios. A medição de recursos
aguarda qualificação nativa; consumo do processo de testes não é consumo do
runtime. AND-01/02 e ativação de produção continuam abertos.
