# Checkpoint storage preparation

This is the first storage-only increment of ADR-042. It is **not connected to
Open, mutation execution, the administrative API, CLI or Web interface**. The v1
journal remains authoritative, including its existing receipt and journal limits.
This increment does not close AND-01 or persistent AND-02, compact history, admit
5000 cycles, or authorize routed/NAT activation.

## Boundary and format

The private `prepareCheckpoint` method serializes against the service mutex and
an advisory workspace lock. A caller-provisioned, separate, private directory
descriptor is required. The live journal inode, aliases, unrecognized entries,
links, inappropriate ownership/permissions and oversized files are refused before
checkpoint publication. The two fixed image names are never overwritten.

Linux image publication uses `renameat2(RENAME_NOREPLACE)` relative to a verified
workspace directory descriptor. A competing destination created after the
existence guard is preserved, including a symlink; unsupported kernel/filesystem
operations are refused without a replacing-rename fallback. Owner, temporary and
previous-manifest creation use exclusive writes. Only selecting the current
manifest intentionally replaces its prior selection through atomic rename.

The image contains the complete validated state, unchanged v1 receipts, original
journal sequence/tip hash and an ownership binding derived from the registered
source journal. Every source record is revalidated in sequence without retaining
historical states. The reader verifies selected image state against its original
journal record; it never replaces `Service.state` or applies a traffic engine.

Files are written exclusively, checked, synchronized, renamed and followed by
directory synchronization. Before renaming an image or selecting a manifest, its
bounded readback must retain the identity, size and timestamp of the original
synchronized descriptor as well as the exact expected bytes. A different inode
with identical bytes does not inherit that durability. The selected manifest contains format, sequence,
generation and hashes. A second publication retains the first image and first
manifest. Repeating the same journal sequence is idempotent; a third different
publication is refused until a separately reviewed lifecycle exists. There is no
automatic repair, deletion, garbage collection or fallback that silently selects
an earlier configuration.

Unknown checkpoint formats and noncanonical/duplicate JSON fields are rejected.
This is codec-level format rejection, **not** a migration or complete engine
downgrade safeguard. The separate workspace does not change the live v1 layout,
so the existing engine can still reopen and resolve its retained replay keys.
Checksums detect corruption; they do not authenticate against root or another
writer with equivalent privileges.

## Storage, interruption and validation

Both source and workspace headroom are observed before image writes, accounting
for duplicate images, temporary selection data and recovery allowance. These
checks do not allocate blocks/inodes, enforce quotas or reserve capacity against
other writers. A write/sync failure remains an error. Partial files are retained
for inspection; they are not guessed to be disposable and are never repaired by
deleting protected history.

The tests use real files and the existing transaction coordinator, with simulated
traffic engines. They exercise state/receipt preservation, v1 reopening and replay,
two complete selections, faults around write/sync/rename/selection, actual child
process exits and reopening, conflicting writers, corruption, substitutions and
low-capacity admission. Process-exit hooks are not physical power-loss tests.

```sh
go test -race ./internal/configpoc
go vet ./internal/configpoc
go test ./internal/configpoc -run '^$' -bench '^BenchmarkCheckpointPreparation$' -benchtime=12x -benchmem
```

The benchmark measures preparation of a minimal initialized journal on its test
filesystem. It is not a Debian appliance benchmark or evidence of enforced storage
isolation. No extra daemon, listener or periodic job is installed.

## ES

Preparación interna, sin activar en el motor: dos imágenes completas y manifiesto
atómico con copia previa. Conserva todos los recibos e historial v1; no compacta,
no migra y no cierra AND-01/02. La tercera publicación se rechaza. Las pruebas de
interrupción no demuestran resistencia a cortes eléctricos; la admisión de espacio
no equivale a cuotas ni reserva física.

## PT

Preparação interna, sem ativação no motor: duas imagens completas e manifesto
atômico com cópia anterior. Preserva todos os recibos e histórico v1; não compacta,
não migra e não resolve AND-01/02. A terceira publicação é recusada. Os testes de
interrupção não comprovam resistência a cortes de energia; a admissão de espaço
não equivale a cotas ou reserva física.
