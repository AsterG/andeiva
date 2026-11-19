# Espera de adquisición WAN inicial, versión 1

Nota de cambio: el controlador DHCP enrutado experimental distingue la espera de adquisición inicial de un fallo que exige recuperación. La respuesta de espera no contiene una concesión ni modifica la red o la configuración. Conserva una cualificación de integridad ya completada; nunca crea disponibilidad ni autoriza tráfico.

El productor lee atómicamente la fase de adquisición y la concesión. La espera requiere una adquisición confirmada y viva que nunca haya concedido una dirección ni recibido una revocación. El helper comprueba que el trabajo seleccionado esté liberado y el forwarding cerrado antes de responder, sin efectos sobre el gate o el gestor de concesiones. Versiones desconocidas, respuestas malformadas, cancelación, EOF, muerte del propietario, expiración y cualquier incertidumbre posterior a efectos mantienen el comportamiento de fallo. Ninguna petición pública puede fabricar este estado. Los pares antiguos rechazan la nueva respuesta en lugar de interpretarla como una concesión.

Las pruebas usan tuberías privadas y el codec de control reales, con dobles explícitos de adquisición, kernel y almacenamiento. No prueban integración DHCP nativa. La adquisición a través del controlador completo y las mediciones de recursos siguen pendientes. No se añaden procesos, temporizadores ni archivos persistentes; begin incorpora una consulta nueva al propietario dentro del plazo original.

Reproducción con Go 1.27.4 en Linux/WSL:

```sh
go test -race ./internal/dhcpclient ./internal/firewallipc ./internal/previewruntime -run 'TestInitialAcquisition|TestRoutedDHCP|TestRoutedIntegrity|TestConservativeLease|TestReconfigure' -count=1 -timeout=120s
go vet ./internal/dhcpclient ./internal/firewallipc ./internal/previewruntime
go test -c -o /tmp/andeiva-dhcp-waiting-v1.test ./internal/previewruntime
```

Revertir el cambio restaura el comportamiento anterior de recuperación obligatoria; no restaura concesiones ni amplía plazos. No se introduce un procedimiento de instalación o activación.
