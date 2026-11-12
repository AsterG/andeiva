import type { Locale } from '../messages.js';

const en = {
  title: 'Network interfaces', intro: 'Interface observations from the managed data plane.',
  loading: 'Loading interfaces', unavailable: 'Interfaces unavailable', unavailableHint: 'The current observation could not be verified. No interface state is assumed.',
  refresh: 'Refresh interfaces', interface: 'Interface', address: 'Addresses', mac: 'MAC address', mtu: 'MTU', state: 'State',
  up: 'Enabled', down: 'Disabled', running: 'Reported active', inactive: 'Reported inactive', empty: 'No interfaces were reported.',
  none: 'Not reported', hint: 'A reported active flag does not prove cable connectivity, Internet access or a valid DHCP lease.',
};
export type RoutingMessages = typeof en;
export const routingMessages: Record<Locale, RoutingMessages> = {
  en,
  es: {
    title: 'Interfaces de red', intro: 'Observaciones de las interfaces del plano de datos administrado.',
    loading: 'Cargando interfaces', unavailable: 'Interfaces no disponibles', unavailableHint: 'No se pudo verificar la observación actual. No se presupone ningún estado de las interfaces.',
    refresh: 'Actualizar interfaces', interface: 'Interfaz', address: 'Direcciones', mac: 'Dirección MAC', mtu: 'MTU', state: 'Estado',
    up: 'Habilitada', down: 'Deshabilitada', running: 'Actividad indicada', inactive: 'Inactividad indicada', empty: 'No se informaron interfaces.',
    none: 'Sin información', hint: 'El indicador de actividad no demuestra conexión del cable, acceso a Internet ni una concesión DHCP válida.',
  },
  pt: {
    title: 'Interfaces de rede', intro: 'Observações das interfaces do plano de dados gerenciado.',
    loading: 'Carregando interfaces', unavailable: 'Interfaces indisponíveis', unavailableHint: 'Não foi possível verificar a observação atual. Nenhum estado das interfaces é presumido.',
    refresh: 'Atualizar interfaces', interface: 'Interface', address: 'Endereços', mac: 'Endereço MAC', mtu: 'MTU', state: 'Estado',
    up: 'Habilitada', down: 'Desabilitada', running: 'Atividade informada', inactive: 'Inatividade informada', empty: 'Nenhuma interface foi informada.',
    none: 'Sem informação', hint: 'O indicador de atividade não comprova conexão do cabo, acesso à Internet nem uma concessão DHCP válida.',
  },
};
