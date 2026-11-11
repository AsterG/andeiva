import type { Locale } from '../messages.js';

const en = {
  about: 'About ANDEIVA', intro: 'Product identity reported by the running appliance.',
  product: 'Product', version: 'Installed version', channel: 'Channel', experimental: 'Alpha Preview · experimental', development: 'Development build',
  noVersion: 'No packaged version', updates: 'Update availability', updateUnavailable: 'Unavailable',
  updateHint: 'This version cannot check whether updates are available.',
  sourceHint: 'Version of the connected appliance.',
  loading: 'Reading product information…', unavailable: 'Product information unavailable', unavailableHint: 'The version could not be verified. Retry the information request; configuration actions are unaffected.',
  refresh: 'Refresh information', footer: 'ANDEIVA version',
};
export type SystemMessages = typeof en;
export const systemMessages: Record<Locale, SystemMessages> = {
  en,
  es: {
    about: 'Acerca de ANDEIVA', intro: 'Identidad del producto informada por el appliance en ejecución.',
    product: 'Producto', version: 'Versión instalada', channel: 'Canal', experimental: 'Alpha Preview · experimental', development: 'Compilación de desarrollo',
    noVersion: 'Sin versión de paquete', updates: 'Disponibilidad de actualizaciones', updateUnavailable: 'No disponible',
    updateHint: 'Esta versión no permite comprobar si hay actualizaciones disponibles.',
    sourceHint: 'Versión del appliance conectado.',
    loading: 'Consultando información del producto…', unavailable: 'Información del producto no disponible', unavailableHint: 'No se pudo verificar la versión. Reintenta la consulta; las acciones de configuración no se ven afectadas.',
    refresh: 'Actualizar información', footer: 'Versión de ANDEIVA',
  },
  pt: {
    about: 'Sobre o ANDEIVA', intro: 'Identidade do produto informada pelo appliance em execução.',
    product: 'Produto', version: 'Versão instalada', channel: 'Canal', experimental: 'Alpha Preview · experimental', development: 'Compilação de desenvolvimento',
    noVersion: 'Sem versão de pacote', updates: 'Disponibilidade de atualizações', updateUnavailable: 'Indisponível',
    updateHint: 'Esta versão não permite verificar se há atualizações disponíveis.',
    sourceHint: 'Versão do appliance conectado.',
    loading: 'Consultando informações do produto…', unavailable: 'Informações do produto indisponíveis', unavailableHint: 'Não foi possível verificar a versão. Tente consultar novamente; as ações de configuração não são afetadas.',
    refresh: 'Atualizar informações', footer: 'Versão do ANDEIVA',
  },
};
