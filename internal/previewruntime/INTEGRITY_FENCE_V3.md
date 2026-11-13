# Private integrity fence — English

Prepared Linux primitive only; no runtime profile, service or API is activated.
A trusted installer explicitly calls `prepareRoutedIntegrityFenceV3` on a fresh,
dedicated, preopened directory. Its effective UID/GID must match the supplied
nonzero owner IDs; the directory must already be 0700 without access/default
ACLs. Preparation never chowns, repairs, removes, truncates or resets existing
files. Failed preparation can leave an unusable file requiring authorized
offline maintenance with services stopped; startup does not repair it.

The fixed `integrity-fence` file is exactly 4096 preallocated bytes: ASCII
`ANDEIVA-INTEGRITY-FENCE-V3\n`, one binary state byte (0 clean, 1 blocked), then
zero padding. Preparation writes and fsyncs the file and directory. Runtime
opens O_RDWR without append/truncate, NOFOLLOW and NONBLOCK, retains a nonblocking
exclusive flock, and validates owner/group, device/inode, 0600, single link,
allocation, ACL absence and the entire encoding. Every Check compares the named
file against the pinned descriptor and rechecks metadata around the read.

MarkBlocked first latches blocked RAM, then writes only state byte 1 and fsyncs.
Short/error writes and fsync errors remain blocked in RAM and return failure.
Check failures also latch RAM; profile repair or writing a clean byte does not
clear a surviving handle. A valid blocked file can reopen as a locked blocked
handle. Close releases its two owned descriptors, never the borrowed root.
There is no runtime clear method, readiness claim or configuration authority.

The private directory protects against other identities. This is not protection
against a malicious helper-owner process or root replacing storage: inode
continuity is checked for the live handle, while every fresh helper must still
perform cold full integrity qualification. Failed persistence may leave clean
bytes; clean never substitutes for that qualification. No durability against
power loss, physical failure, full disk, or unreliable fsync is claimed here.
Existing independently armed guardian rollback must not call this latch.

Cost is a fixed 4096-byte file, two owned descriptors and bounded 4096-byte read
buffers; no background thread, timer or growing history. Native CPU/RSS and
end-to-end activation remain pending. Tests use real temporary Linux files,
ACLs, hardlinks, FIFOs, flock and race detection; only write/sync failure hooks
are injected. No host settings, services or network configuration are changed.

```sh
go test -race ./internal/previewruntime -run TestRoutedIntegrityFenceV3 -count=3
go vet ./internal/previewruntime
go build ./...
```

# Fence privado de integridad — Español

Primitiva Linux preparada; no activa servicios, API ni perfiles runtime. Un
instalador autorizado prepara explícitamente una raíz dedicada y vacía, ya
0700, con UID/GID efectivos iguales a los IDs no cero recibidos y sin ACL de
acceso/predeterminada. Nunca repara, cambia propietarios, borra ni reinicia
archivos existentes. Una preparación fallida requiere mantenimiento offline
autorizado; el arranque no la corrige.

`integrity-fence` ocupa 4096 bytes preasignados: cabecera ASCII indicada arriba,
byte binario 0/1 y relleno cero. Se sincronizan archivo y directorio. Cada
comprobación valida nombre frente a FD fijado, propietario/grupo, dispositivo,
inodo, modo 0600, enlace único, asignación, ausencia de ACL y formato completo.
Un flock exclusivo impide un segundo propietario cooperante. Cualquier error
bloquea RAM; MarkBlocked escribe sólo el byte 1 después de bloquear RAM y hace
fsync. Errores de escritura/sync nunca habilitan la administración. No existe
método de desbloqueo; Close libera dos FDs propios, no la raíz prestada.

Un helper nuevo siempre necesita comprobación completa en frío, incluso con
byte limpio: un fallo de persistencia puede conservarlo limpio. No se garantiza
resistencia a cortes de energía, disco lleno o fallo físico. Un proceso malicioso
con el mismo UID o root puede reemplazar almacenamiento; la continuidad de inodo
se verifica durante la vida del handle. El rollback autónomo del guardian no
consulta este fence. Archivo fijo, buffers acotados, sin hilos ni historial;
consumo nativo e integración completa pendientes. Los comandos anteriores
reproducen las pruebas locales sin alterar red ni servicios del host.

# Fence privado de integridade — Português

Primitiva Linux preparada; não ativa serviços, API ou perfis runtime. Um
instalador autorizado prepara explicitamente uma raiz dedicada e vazia, já
0700, com UID/GID efetivos iguais aos IDs não zero recebidos e sem ACL de acesso
ou padrão. Nunca repara, altera proprietários, remove ou reinicia arquivos
existentes. Falha na preparação exige manutenção offline autorizada; o boot
não a corrige automaticamente.

`integrity-fence` possui 4096 bytes pré-alocados: cabeçalho ASCII acima, byte
binário 0/1 e preenchimento zero. Arquivo e diretório são sincronizados. Cada
verificação compara nome e FD fixado, proprietário/grupo, dispositivo, inode,
modo 0600, link único, alocação, ausência de ACL e formato completo. Um flock
exclusivo impede um segundo proprietário cooperante. Qualquer erro bloqueia
RAM; MarkBlocked escreve somente o byte 1 após bloquear RAM e executa fsync.
Falhas de escrita/sync nunca liberam administração. Não existe método de
limpeza; Close libera dois FDs próprios, não a raiz emprestada.

Um novo helper sempre exige verificação completa a frio, mesmo com byte limpo:
falhas de persistência podem conservá-lo limpo. Não há garantia contra queda de
energia, disco cheio ou falha física. Processo malicioso com mesmo UID ou root
pode substituir armazenamento; a continuidade do inode é verificada durante a
vida do handle. O rollback autônomo do guardian não consulta este fence.
Arquivo fixo, buffers limitados, sem threads ou histórico crescente; consumo
nativo e integração completa pendentes. Os comandos acima reproduzem testes
locais sem alterar rede ou serviços do host.
