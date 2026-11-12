# Ensamblaje del helper de lectura seleccionada

OpenRoutedHelperV3 es una fábrica del supervisor, no un endpoint ni una activación
de servicios. Recibe cuatro directorios fijados y abre pools exclusivamente como
lectura. Verifica identidades, roles, 18 slots, capacidades y ausencia de alias.

Exige UID del helper, grupo primario IPC, grupos suplementarios limitados a IPC y
lector, NoNewPrivs y exactamente CAP_NET_ADMIN en las cinco máscaras. El grupo
lector es común a los cuatro directorios y distinto del grupo primario API.
Comprueba BootID y namespace reales frente a metadatos confiables. No cambia los
validadores v1/v2.

Compone lector seleccionado, fuente y sesión v3 existentes. No exige una
activación seleccionada antes del primer handshake: el nuevo escritor necesita
esa exclusión antes de publicar su Intent de arranque autorizado. Cada efecto
posterior verifica selección, G1, reservas, Scope y operación independientemente.

Serve sólo acepta un socket heredado y PID API fijados por el supervisor, con
credenciales verificadas por el kernel. Desconectar el controlador no cierra el
helper ni su guardián. Close cancela canales y cierra lectores propios; no toca
autoridad, reglas, listeners o namespaces. Los roots son prestados. El servidor
v2 de compatibilidad debe quedar restringido a lectura durante toda su vida.

Las pruebas usan archivos reales de formato compartido, comprueban O_RDONLY y
rechazan sustituciones, alias y perfiles incorrectos; verifican limpieza parcial.
Las identidades de fixtures no representan un helper privilegiado real. El motor
y guardián son simulados para comprobar desconexión y expiración independiente.
No acreditan nftables nativo, lanzamiento del supervisor, permisos entre tres
procesos, transporte completo con selección ni unidades desplegadas.

Linux: go test -race ./internal/previewruntime -run TestRoutedHelperV3 -count=1

El transporte preparado `routedKernelV3` sólo ejecuta nft con comandos y tres
nombres de tabla fijos dentro del namespace verificado. Recibe los lotes
generados por entrada estándar. Limita entrada y cada salida a 512 KiB y cada
proceso a dos segundos dentro del plazo del llamador. Distingue ausencia tras
consulta completa de un fallo; presencia no acredita propiedad. Laboratorio y
helper comparten el decodificador puro. Rechaza ejecución en el host y enums
arbitrarios. No está conectado a una unidad desplegada; quedan pendientes las
pruebas nativas de procesos, tráfico y consumo.
