import type { Locale } from '../messages.js';
const en = {
  title: 'Rule traffic observations', description: 'On-request counter samples for explicit rules only. These are not packet or connection logs; default-policy traffic is not recorded here.',
  sample: 'Sample and refresh', older: 'Older observations', loading: 'Reading observations…',
  retention: 'Up to 512 records are held in API process memory. Restarting the API clears this history. Older pages do not collect a new sample.',
  initial: 'No sample loaded. Request a sample to read real rule counters.', empty: 'No observations in this page.',
  baselineHint: 'A baseline establishes totals after an initial sample, reset or policy reapplication. No delta is available for that observation.',
  changed: 'Observation history restarted', changedBody: 'The API observation stream changed. Previous records were cleared. Request a fresh sample to continue.',
  truncated: 'Earlier observations are no longer retained', truncatedBody: 'Some earlier observations were removed by retention. This page is not the complete history. Request a fresh sample to return to the latest page.',
  stream: 'Observation stream', evicted: 'Records removed by retention', count: 'Records in this page',
  sequence: 'Sequence', time: 'Observed at (not packet time)', since: 'Since observation', revision: 'Policy revision', rule: 'Rule ID', action: 'Action', kind: 'Sample kind',
  baseline: 'Baseline', delta: 'Delta', noDelta: 'Not available — baseline', noSince: 'Not available',
  packetsTotal: 'Packets total', bytesTotal: 'Bytes total', packetsDelta: 'Packets delta', bytesDelta: 'Bytes delta', allow: 'Allow', deny: 'Deny',
};
export type TrafficMessages = typeof en;
const es: TrafficMessages = {
  title: 'Observaciones de tráfico por regla', description: 'Muestras de contadores bajo demanda para reglas explícitas. No son registros de paquetes ni conexiones; no incluyen tráfico de la política predeterminada.',
  sample: 'Muestrear y actualizar', older: 'Observaciones anteriores', loading: 'Leyendo observaciones…',
  retention: 'Se conservan hasta 512 registros en memoria del proceso API. Reiniciar el API borra este historial. Las páginas anteriores no toman una nueva muestra.',
  initial: 'Sin muestra cargada. Solicite una muestra para leer contadores reales por regla.', empty: 'No hay observaciones en esta página.',
  baselineHint: 'La muestra inicial establece totales tras la primera lectura, un reinicio de contadores o la reaplicación de una política. Esa observación no tiene diferencias disponibles.',
  changed: 'Se reinició el historial de observaciones', changedBody: 'Cambió la secuencia del proceso API. Los registros anteriores se eliminaron. Solicite una muestra nueva para continuar.',
  truncated: 'Las observaciones anteriores ya no se conservan', truncatedBody: 'La retención eliminó algunas observaciones anteriores. Esta página no contiene todo el historial. Solicite una muestra nueva para volver a la página más reciente.',
  stream: 'Secuencia de observación', evicted: 'Registros eliminados por retención', count: 'Registros en esta página',
  sequence: 'Número', time: 'Fecha de observación (no del paquete)', since: 'Desde la observación', revision: 'Revisión de política', rule: 'ID de regla', action: 'Acción', kind: 'Tipo de muestra',
  baseline: 'Muestra inicial', delta: 'Diferencia', noDelta: 'No disponible — muestra inicial', noSince: 'No disponible',
  packetsTotal: 'Total de paquetes', bytesTotal: 'Total de bytes', packetsDelta: 'Diferencia de paquetes', bytesDelta: 'Diferencia de bytes', allow: 'Permitir', deny: 'Denegar',
};
const pt: TrafficMessages = {
  title: 'Observações de tráfego por regra', description: 'Amostras de contadores sob demanda para regras explícitas. Não são registros de pacotes ou conexões; não incluem tráfego da política padrão.',
  sample: 'Amostrar e atualizar', older: 'Observações anteriores', loading: 'Lendo observações…',
  retention: 'Até 512 registros ficam na memória do processo API. Reiniciar a API apaga este histórico. Páginas anteriores não coletam uma nova amostra.',
  initial: 'Nenhuma amostra carregada. Solicite uma amostra para ler contadores reais por regra.', empty: 'Nenhuma observação nesta página.',
  baselineHint: 'A amostra inicial estabelece totais após a primeira leitura, reinício dos contadores ou reaplicação de uma política. Não há diferença disponível para essa observação.',
  changed: 'O histórico de observações reiniciou', changedBody: 'A sequência do processo API mudou. Os registros anteriores foram removidos. Solicite uma nova amostra para continuar.',
  truncated: 'As observações anteriores não estão mais retidas', truncatedBody: 'A retenção removeu algumas observações anteriores. Esta página não contém todo o histórico. Solicite uma nova amostra para voltar à página mais recente.',
  stream: 'Sequência de observação', evicted: 'Registros removidos pela retenção', count: 'Registros nesta página',
  sequence: 'Número', time: 'Data da observação (não do pacote)', since: 'Desde a observação', revision: 'Revisão da política', rule: 'ID da regra', action: 'Ação', kind: 'Tipo da amostra',
  baseline: 'Amostra inicial', delta: 'Diferença', noDelta: 'Indisponível — amostra inicial', noSince: 'Indisponível',
  packetsTotal: 'Total de pacotes', bytesTotal: 'Total de bytes', packetsDelta: 'Diferença de pacotes', bytesDelta: 'Diferença de bytes', allow: 'Permitir', deny: 'Negar',
};
export const trafficMessages: Record<Locale, TrafficMessages> = { en, es, pt };
