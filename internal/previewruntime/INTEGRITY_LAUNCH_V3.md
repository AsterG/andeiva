# Explicit integrity launch profile

## English

This opt-in extends the existing trusted grouped launcher; it does not activate
installed services. `RoutedLaunchResourcesV3.IntegrityRoot` is a supervisor-pinned
directory owned by the helper UID and IPC GID, mode 0700 without POSIX ACLs.
Its fixed marker must already exist. Opening runtime never prepares or repairs it.

The root installer explicitly calls
`PrepareRoutedIntegrityLaunchV3(ctx, identities, root, stderr)` on an empty,
already-owned directory. The current trusted binary must dispatch the fixed
`RoutedIntegrityPrepareRoleV3` argument to
`RunRoutedIntegrityPrepareRoleV3(ctx)` and exit with its result. The supervisor
uses a capless helper-identity child, clear supplementary groups, no-new-privileges,
and only inherited FD3. Trusted numeric environment values bind helper UID/GID
and the root parent PID. The child checks actual credentials, capabilities,
parent identity and directory profile before exclusive preparation. Existing
markers are refused; no chown, reset, namespace entry or runtime preparation occurs.

Runtime children retain the existing FD3–12 layout. The integrity helper alone
also inherits the private directory at FD13; the API never receives that root.
Both receive an explicit supervisor bootstrap modality. The API then requires
the four-capability integrity handshake; it cannot fall back to the ordinary
three-capability profile. The helper adopts and verifies FD13 before opening
other roots, rejecting aliasing and mismatched ownership or permissions.

The caller retains all supervisor roots through child termination. Child-owned
duplicates close after runtime drains. Unit tests validate directory/process
profiles; actual installer dispatch and a three-UID native launch still require
integration qualification. No host networking or installed service is changed.
A new helper reopening a blocked marker has no historical RAM anchor: it stays
fenced and does not promise automatic offline recovery or new Confirm authority.

## Español

Este perfil es explícito y no activa servicios instalados. `IntegrityRoot` es un
directorio fijado por el supervisor, propiedad del UID helper y GID IPC, modo
0700 y sin ACL POSIX. El instalador llama a `PrepareRoutedIntegrityLaunchV3`
sobre un directorio vacío ya preparado; el binario debe despachar el rol fijo
`RoutedIntegrityPrepareRoleV3` hacia `RunRoutedIntegrityPrepareRoleV3` y terminar.
El hijo usa la identidad helper sin capacidades, sin grupos adicionales y con
no-new-privileges. Solo recibe FD3 y parámetros numéricos confiables. No cambia
propietarios, repara ni reinicia marcadores, ni modifica redes.

Solo el helper recibe el directorio privado en FD13. La API conserva FD3–12 y
exige el handshake de integridad sin fallback. El supervisor conserva las raíces
hasta terminar los hijos. Las pruebas unitarias no sustituyen la validación
nativa del instalador y del lanzamiento con tres UID. Un helper nuevo con
marcador bloqueado permanece bloqueado sin prometer recuperación automática.

## Português

Este perfil explícito não ativa serviços instalados. `IntegrityRoot` é um
diretório fixado pelo supervisor, pertencente ao UID helper e GID IPC, modo 0700
e sem ACL POSIX. O instalador chama `PrepareRoutedIntegrityLaunchV3` sobre um
diretório vazio já preparado; o binário deve encaminhar o papel fixo
`RoutedIntegrityPrepareRoleV3` a `RunRoutedIntegrityPrepareRoleV3` e terminar.
O filho usa a identidade helper sem capacidades, sem grupos adicionais e com
no-new-privileges. Recebe apenas FD3 e parâmetros numéricos confiáveis. Não
altera proprietários, repara ou reinicia marcadores, nem modifica redes.

Apenas o helper recebe o diretório privado em FD13. A API mantém FD3–12 e exige
o handshake de integridade sem fallback. O supervisor retém as raízes até o
encerramento dos filhos. Os testes unitários não substituem a validação nativa
do instalador e do lançamento com três UID. Um helper novo com marcador
bloqueado permanece bloqueado, sem prometer recuperação automática.
