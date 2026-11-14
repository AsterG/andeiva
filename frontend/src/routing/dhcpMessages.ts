import type { Locale } from '../messages.js';

const en = {
  title: 'LAN DHCP configuration', scope: 'Scope', addScope: 'Add scope', editScope: 'Edit scope', remove: 'Remove',
  hint: 'Configuration only. This view does not verify a running DHCP service or assigned leases. Changes use the shared Local edits, Prepare changes, Validate, Apply with confirmation and Save for restart workflow.',
  enabled: 'Enable LAN DHCP in configuration', disabled: 'Disabled in configuration', configured: 'Enabled in configuration',
  retained: 'Disabling retains all scope settings. It does not change WAN addressing or authorize forwarding.',
  empty: 'No DHCP scopes configured.', noLAN: 'Select a static LAN in the network configuration first.',
  id: 'Scope ID', binding: 'Static LAN interface', subnet: 'Subnet', router: 'Router', pools: 'Address pools', first: 'First address', last: 'Last address', addPool: 'Add pool',
  excluded: 'Excluded addresses', dns: 'DNS servers', ntp: 'NTP servers', listHint: 'Separate IPv4 addresses with commas. Leave empty for none.',
  reservations: 'Reservations', addReservation: 'Add reservation', mac: 'MAC address', address: 'Reserved address', domain: 'Domain (optional)',
  lease: 'Lease (seconds)', renew: 'Renew T1 (seconds)', rebind: 'Rebind T2 (seconds)', timers: '60–604800 seconds per lease; 0 < T1 < T2 < lease.',
  save: 'Keep scope in local draft', cancel: 'Cancel', error: 'Check DHCP settings', invalid: 'Use unique scope IDs and static LANs. Pools must be non-overlapping usable hosts within the LAN subnet. Exclude the router if inside a pool. Reservations require unique unicast MACs and host addresses, distinct from exclusions and router. Check DNS/NTP, domain and lease timers.',
  limits: 'Up to 32 scopes and pools per scope, 256 exclusions and reservations per scope, 4 DNS/NTP servers, and 65536 pooled addresses in total.',
};
type Copy = typeof en;
export const dhcpMessages: Record<Locale, Copy> = {
  en,
  es: {
    title: 'Configuración DHCP LAN', scope: 'Ámbito', addScope: 'Añadir ámbito', editScope: 'Editar ámbito', remove: 'Eliminar',
    hint: 'Sólo configuración. Esta vista no verifica un servicio DHCP activo ni concesiones asignadas. Los cambios utilizan el flujo compartido Ediciones locales, Preparar cambios, Validar, Aplicar con confirmación y Guardar para reiniciar.',
    enabled: 'Habilitar DHCP LAN en la configuración', disabled: 'Deshabilitado en la configuración', configured: 'Habilitado en la configuración',
    retained: 'Deshabilitar conserva todos los ajustes de los ámbitos. No cambia el direccionamiento WAN ni autoriza reenvío.',
    empty: 'No hay ámbitos DHCP configurados.', noLAN: 'Seleccione primero una LAN estática en la configuración de red.',
    id: 'ID del ámbito', binding: 'Interfaz LAN estática', subnet: 'Subred', router: 'Router', pools: 'Rangos de direcciones', first: 'Primera dirección', last: 'Última dirección', addPool: 'Añadir rango',
    excluded: 'Direcciones excluidas', dns: 'Servidores DNS', ntp: 'Servidores NTP', listHint: 'Separe las direcciones IPv4 con comas. Déjelo vacío para ninguna.',
    reservations: 'Reservas', addReservation: 'Añadir reserva', mac: 'Dirección MAC', address: 'Dirección reservada', domain: 'Dominio (opcional)',
    lease: 'Concesión (segundos)', renew: 'Renovación T1 (segundos)', rebind: 'Revinculación T2 (segundos)', timers: '60–604800 segundos por concesión; 0 < T1 < T2 < concesión.',
    save: 'Conservar ámbito en borrador local', cancel: 'Cancelar', error: 'Revise los ajustes DHCP', invalid: 'Utilice IDs y LAN estáticas únicos. Los rangos deben contener hosts utilizables de la subred, sin solaparse. Excluya el router si está dentro de un rango. Las reservas requieren MAC unicast y direcciones únicas, distintas de exclusiones y router. Revise DNS/NTP, dominio y temporizadores.',
    limits: 'Hasta 32 ámbitos y rangos por ámbito, 256 exclusiones y reservas por ámbito, 4 servidores DNS/NTP y 65536 direcciones agrupadas en total.',
  },
  pt: {
    title: 'Configuração DHCP LAN', scope: 'Escopo', addScope: 'Adicionar escopo', editScope: 'Editar escopo', remove: 'Remover',
    hint: 'Somente configuração. Esta vista não verifica um serviço DHCP ativo nem concessões atribuídas. As alterações usam o fluxo compartilhado Edições locais, Preparar alterações, Validar, Aplicar com confirmação e Salvar para reiniciar.',
    enabled: 'Habilitar DHCP LAN na configuração', disabled: 'Desabilitado na configuração', configured: 'Habilitado na configuração',
    retained: 'Desabilitar preserva todos os ajustes dos escopos. Não altera o endereçamento WAN nem autoriza encaminhamento.',
    empty: 'Nenhum escopo DHCP configurado.', noLAN: 'Selecione primeiro uma LAN estática na configuração de rede.',
    id: 'ID do escopo', binding: 'Interface LAN estática', subnet: 'Sub-rede', router: 'Roteador', pools: 'Intervalos de endereços', first: 'Primeiro endereço', last: 'Último endereço', addPool: 'Adicionar intervalo',
    excluded: 'Endereços excluídos', dns: 'Servidores DNS', ntp: 'Servidores NTP', listHint: 'Separe os endereços IPv4 com vírgulas. Deixe vazio para nenhum.',
    reservations: 'Reservas', addReservation: 'Adicionar reserva', mac: 'Endereço MAC', address: 'Endereço reservado', domain: 'Domínio (opcional)',
    lease: 'Concessão (segundos)', renew: 'Renovação T1 (segundos)', rebind: 'Revinculação T2 (segundos)', timers: '60–604800 segundos por concessão; 0 < T1 < T2 < concessão.',
    save: 'Manter escopo no rascunho local', cancel: 'Cancelar', error: 'Verifique os ajustes DHCP', invalid: 'Use IDs e LANs estáticas únicos. Os intervalos devem conter hosts utilizáveis da sub-rede, sem sobreposição. Exclua o roteador se estiver em um intervalo. As reservas exigem MACs unicast e endereços únicos, distintos de exclusões e roteador. Verifique DNS/NTP, domínio e temporizadores.',
    limits: 'Até 32 escopos e intervalos por escopo, 256 exclusões e reservas por escopo, 4 servidores DNS/NTP e 65536 endereços agrupados no total.',
  },
};
