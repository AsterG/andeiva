# Diagnóstico nativo de aquisição DHCP

Instrumentação experimental de laboratório; não comprova WAN funcional. O prazo de aquisição permanece em 35 segundos. Somente o responsável pelo supervisor executa o harness nativo isolado após revisão independente.

Compilar um artefato separado, nunca empacotá-lo ou implantá-lo:

```sh
go test -c -tags andeiva_native_dhcp_diagnostics -o /tmp/andeiva-dhcp-jobs-diagnostics-v4.test ./internal/previewruntime
```

Registrar o commit exato e SHA-256. A compilação comum descarta stderr e não cria arquivo, registro, worker ou timer de diagnóstico. A fixture também informa tempos limitados das chamadas reconcile/current/live existentes, sem RPC adicional de autoridade.

O artefato classifica stderr por códigos fixos e registra motivos validados do hook, etapas de falha e tempos BOOTTIME. Não mantém opções, endereços, hostnames ou frames brutos, nem adiciona outro leitor ao pipe do protocolo. Cria exclusivamente um arquivo root0600 em diretório root0700 no tmpfs privado existente: `/run/andeiva-dhcp/native-diagnostics/events.jsonl`. Limite de 64 KiB, marcador explícito de truncamento e descarte posterior.

A fixture registra um único consumidor antes da inicialização. Após validar o bootstrap root, verifica handle real, pidfd/start ticks, identidades de rede/mount e cgroup; retém o diretório antes de Activate. Coleta enquanto o producer vive e antes do cleanup, sem redescobrir PID após teardown. Libera explicitamente registro e pins. Diagnóstico indisponível reprova a fixture diagnóstica, sem aprovar aquisição silenciosamente.

Exigir testes com/sem tag, race, vet e compilação antes do native executado por root. Este perfil não autoriza ampliar prazos, privilégios, políticas de pacotes ou relaxar inspeção. Sua sobrecarga não representa benchmark de produção.

Diagnóstico de duração: os hooks de concessão aceitos incluem apenas o número validado `lease_seconds`; a expiração não inventa duração. T1/T2 não fazem parte do evento validado e não são inferidos. A trilha distingue erros de canal, espera inicial, conflito, armazenamento e capacidade; registra mudanças de classe dentro do mesmo limite de 24 registros. Os campos opcionais de época e trabalho são uma leitura posterior à chamada sem bloqueio, não uma prova da operação exata que falhou. Nenhum erro, opção, endereço ou nome sem filtragem é adicionado.

Trilha por verbo: o artefato de diagnóstico mantém no máximo 63 registros fixos em memória por processo. As chamadas usam TryLock; perdas por contenção ou capacidade são declaradas em um resumo adicional. O registro não realiza I/O nem acrescenta workers, temporizadores ou RPC. Somente após o término do papel nativo fixo de API/helper, TestMain grava os registros em seu stderr privado, fora do mutex, com limite total de 64 registros/32 KiB. Uma falha anterior do papel é preservada se a gravação também falhar. São registradas apenas classes fixas de lado, verbo, erro e contexto, duração e BOOTTIME. A morte abrupta pode perder essa evidência em memória. A compilação de produção não cria o registrador nem lê relógios para essa função. A observação não altera o prazo RPC de três segundos nem valida um orçamento agregado de reconciliação.

Os pontos de falha do helper compartilham registrador e capacidade, com lado
`helper_stage` e código fixo. Distinguem estado/seleção de Open, proprietário,
preparação/abertura do gate e forwarding; fechamento, seleção, recuperação,
retirada de concessão e readback; e verificações internas de autoridade/política.
Não mantêm hash de Work, endereço, caminho ou erro bruto. As condições preservam
ordem, curto-circuito e número de chamadas. O build comum nem consulta o contexto
por meio desses hooks de diagnóstico.

A fixture também coleta linhas novas de esquema fixo após o Close existente.
Não altera EOF de controle, drenagem ou limite original de parada de quatro
segundos. Assim preserva saída do helper posterior ao primeiro relato de falha.
A ausência anterior não prova encerramento forçado; morte abrupta ou log limitado
cheio ainda podem perder evidência. Não se infere aquisição WAN bem-sucedida nem
a causa de uma falha nativa.
