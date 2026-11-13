# Fixture de integración IPC routed v3 — RED

`TestRoutedIPCV3SharedStoreLifecycle` usa store compartido, reservas R2, G1,
lector seleccionado, RoutedStoreSourceV3, wrapper Unix con credenciales reales,
RoutedSessionV3, RoutedRemoteAuthority y Group. Sólo I/O kernel/red usa fixtures
tipadas. Corre en Linux sin root. UID2000 del helper es scope lógico distinto
del dueño real del store; no prueba aislamiento de tres UIDs ni tráfico nativo.

El freeze permanece RED: Boot4 conserva las dos reglas importadas sin L3;
Stage4/Validate4/Commit4/Confirm4/Save4 pasan. Después de Stage6, Validate6 devuelve
ANDEIVA_ADMIN_HELPER_UNAVAILABLE. Sin race, WSL/Go1.27.4: PrepareView 43/581/920 ms
y luego 3.000320499 s con error de lectura seleccionada; Resolve arm/apply/confirm
1.027/1.167/1.494 s. La sesión termina ANDEIVA_PREVIEW_UNAVAILABLE. Total10.447 s.
No se cambian timeouts, validadores ni protocolo. Restart confirmado e inversa
están escritos pero no alcanzados; expiración y aceptación completa quedan
pendientes del fix del lector. No es calificación nativa de Boot4.

Reproducir con Go1.27.4, caché offline y usuario Linux no root (root omite este perfil):

```sh
GOPROXY=off GOSUMDB=off go test ./internal/previewruntime -run '^TestRoutedIPCV3SharedStoreLifecycle$' -count=1 -timeout=10m -v
```

Sólo la fixture convierte directorios temporales a02750 y archivos a0640 después
de cerrar writers privados; checkpoint.lock queda0600. No cambia permisos de
producción. Handshake Unix precede cada apertura del writer compartido. Ninguna
ruta/hash de fixture concede autoridad.
