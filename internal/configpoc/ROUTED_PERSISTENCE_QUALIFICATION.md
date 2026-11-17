# Routed persistence qualification

Run from a Linux checkout without privileges:

```sh
bash packaging/preview/tests/routed-persistence.sh
```

The bounded harness reuses sixteen existing tests with `-race`, no cache reuse,
and a five-minute test deadline. Every named test must run and pass once; skips,
missing tests, failed subprocesses and oversized evidence fail qualification.
It changes no runtime configuration, installed service or host networking.

| Contract | Existing evidence |
| --- | --- |
| Commit/Confirm, explicit Save, history rollback | Coordinator lifecycle, wrong-confirmation and verified-history tests |
| Unconfirmed timeout and process restart | Automatic timeout and immutable-outcome restart tests |
| Routed group and exact rollback | NoServices stage/replace/commit and DHCP LAN-inventory tests |
| Process restart preserves unsaved Running | FreshScope service restart with Running deny and Startup allow |
| OS boot selects Startup | Boot identity, interrupted subprocess boundaries and reboot-scope tests |
| No old DHCP authority after OS boot | DHCP scope retirement and old-clock rejection tests |

These tests use real durable stores, audit/history validation and coordinators,
with modeled network authorities or simulated persistent engines. They do not
prove a native appliance reboot, Kea startup, packet forwarding or API recovery
with a retained live V4 DHCP owner. Those remain separate integration gates.
An active selected DHCP Work currently blocks independent configuration
publication. The existing native jobs fixture checks that an active-work
rollback is refused; it does not prove a successful live rollback or Save.
This harness does not relax that boundary or provide a transactional handoff.
There is no product resource delta: this change is a developer test entry point.
Qualification CPU/RAM observations describe the test runner, not appliance sizing.

## Español

El arnés reutiliza dieciséis pruebas existentes de Commit/Confirm, Save explícito,
rollback y reinicio con almacenes reales y autoridades de red simuladas. Exige
que cada prueba se ejecute y pase; rechaza omisiones y evidencia incompleta.
No prueba un reinicio nativo del appliance, Kea, tráfico real ni recuperación de
API con el propietario DHCP V4 conservado. No modifica servicios ni red del host.
El trabajo DHCP activo bloquea publicaciones independientes; no se declara
calificado un rollback o Save en caliente mientras ese trabajo siga activo.

## Português

O executor reutiliza dezesseis testes existentes de Commit/Confirm, Save explícito,
rollback e reinício com armazenamento real e autoridades de rede simuladas.
Cada teste deve executar e passar; omissões e evidências incompletas são rejeitadas.
Não comprova reinício nativo do appliance, Kea, tráfego real ou recuperação da
API com o proprietário DHCP V4 preservado. Não altera serviços nem a rede do host.
O trabalho DHCP ativo bloqueia publicações independentes; rollback ou Save com
esse trabalho ativo ainda não estão qualificados.
