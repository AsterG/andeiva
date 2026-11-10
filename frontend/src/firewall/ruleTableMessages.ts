import type { Locale } from '../messages.js';

const en = {
  new: 'New change', modified: 'Modified change', moved: 'Order changed', removed: 'Removed from this draft', enabled: 'Enabled', disabled: 'Disabled', disabledRunning: 'Disabled in Running', notApplicable: 'Not applicable', toggleHint: 'Disabled rules are retained in configuration and omitted from traffic evaluation. Commit applies the change; Save stores the complete Running revision for boot.',
  search: 'Search rules', searchHint: 'ID, IP, protocol or port', service: 'Service', execution: 'Execution', persistence: 'At next boot',
  saved: 'Matches Startup', unsaved: 'Not saved', applied: 'Running', notApplied: 'Not applied', unverified: 'Unverified',
  savedRevision: 'Running revision saved for boot', unsavedRevision: 'Running revision has unsaved changes', saveAll: 'Save stores the entire Running revision, including rule order. Row indicators compare the displayed rule and position; they do not confirm the whole policy.',
  reorder: 'Reorder', reorderHint: 'Drag the six dots. With the handle focused: Space to pick up, arrows or Home/End to choose position, Enter to place, Escape to cancel.',
  filtered: 'Clear filters to reorder the complete policy.', position: 'Move to position', move: 'Move', moving: 'Moving', placed: 'Placed', cancelled: 'Reordering cancelled',
  ruleCount: 'rules', noMatches: 'No rules match these filters.', details: 'Revision details', configuration: 'Configuration changes',
  editorHint: 'Changes stay in the local draft until staged and committed.', changed: 'Local draft differs from Candidate', candidateChanged: 'Candidate differs from Running',
  actionFilter: 'Filter by action', allActions: 'All actions', order: 'Order', counters: 'Observed counters', previous: 'Previous position',
};
export type RuleTableMessages = typeof en;
const es: RuleTableMessages = {
  new: 'Cambio nuevo', modified: 'Modificada', moved: 'Orden modificado', removed: 'Eliminadas de este borrador', enabled: 'Habilitada', disabled: 'Deshabilitada', disabledRunning: 'Deshabilitada en activa', notApplicable: 'No corresponde', toggleHint: 'Las reglas deshabilitadas se conservan en la configuración y no evalúan tráfico. Aplicar activa el cambio; Guardar persiste toda la revisión activa para el arranque.',
  search: 'Buscar reglas', searchHint: 'ID, IP, protocolo o puerto', service: 'Servicio', execution: 'Ejecución', persistence: 'Al reiniciar',
  saved: 'Coincide con Startup', unsaved: 'Sin guardar', applied: 'Activa', notApplied: 'Sin aplicar', unverified: 'Sin verificar',
  savedRevision: 'Revisión activa guardada para arranque', unsavedRevision: 'La revisión activa tiene cambios sin guardar', saveAll: 'Guardar persiste toda la revisión activa, incluido el orden. Los indicadores comparan la regla visible y su posición; no confirman toda la política.',
  reorder: 'Reordenar', reorderHint: 'Arrastre los seis puntos. Con el control enfocado: Espacio para tomar, flechas o Inicio/Fin para elegir posición, Intro para colocar y Escape para cancelar.',
  filtered: 'Quite los filtros para reordenar la política completa.', position: 'Mover a la posición', move: 'Mover', moving: 'Moviendo', placed: 'Colocada', cancelled: 'Reordenación cancelada',
  ruleCount: 'reglas', noMatches: 'Ninguna regla coincide con los filtros.', details: 'Detalles de revisiones', configuration: 'Cambios de configuración',
  editorHint: 'Los cambios permanecen en el borrador local hasta preparar y aplicar.', changed: 'El borrador local difiere de la candidata', candidateChanged: 'La candidata difiere de la activa',
  actionFilter: 'Filtrar por acción', allActions: 'Todas las acciones', order: 'Orden', counters: 'Contadores observados', previous: 'Posición anterior',
};
const pt: RuleTableMessages = {
  new: 'Nova alteração', modified: 'Modificada', moved: 'Ordem alterada', removed: 'Removidas deste rascunho', enabled: 'Habilitada', disabled: 'Desabilitada', disabledRunning: 'Desabilitada em execução', notApplicable: 'Não se aplica', toggleHint: 'As regras desabilitadas permanecem na configuração e não avaliam tráfego. Aplicar ativa a alteração; Salvar persiste toda a revisão em execução para inicialização.',
  search: 'Buscar regras', searchHint: 'ID, IP, protocolo ou porta', service: 'Serviço', execution: 'Execução', persistence: 'Ao reiniciar',
  saved: 'Corresponde a Startup', unsaved: 'Não salva', applied: 'Em execução', notApplied: 'Não aplicada', unverified: 'Não verificada',
  savedRevision: 'Revisão em execução salva para inicialização', unsavedRevision: 'A revisão em execução tem alterações não salvas', saveAll: 'Salvar persiste toda a revisão em execução, incluindo a ordem. Os indicadores comparam a regra exibida e sua posição; não confirmam toda a política.',
  reorder: 'Reordenar', reorderHint: 'Arraste os seis pontos. Com o controle em foco: Espaço para pegar, setas ou Início/Fim para escolher posição, Enter para soltar e Escape para cancelar.',
  filtered: 'Limpe os filtros para reordenar a política completa.', position: 'Mover para posição', move: 'Mover', moving: 'Movendo', placed: 'Posicionada', cancelled: 'Reordenação cancelada',
  ruleCount: 'regras', noMatches: 'Nenhuma regra corresponde aos filtros.', details: 'Detalhes das revisões', configuration: 'Alterações de configuração',
  editorHint: 'As alterações ficam no rascunho local até preparar e aplicar.', changed: 'O rascunho local difere da candidata', candidateChanged: 'A candidata difere da execução',
  actionFilter: 'Filtrar por ação', allActions: 'Todas as ações', order: 'Ordem', counters: 'Contadores observados', previous: 'Posição anterior',
};
export const ruleTableMessages: Record<Locale, RuleTableMessages> = { en, es, pt };
