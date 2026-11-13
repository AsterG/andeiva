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
