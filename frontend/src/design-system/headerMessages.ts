import type { Locale } from '../messages.js';

const en = { preferences: 'Preferences', account: 'Account', role: 'Role', administrator: 'Administrator', viewer: 'Read only', expires: 'Session expires', logout: 'Sign out' };
export const headerMessages: Record<Locale, typeof en> = {
  en,
  es: { preferences: 'Preferencias', account: 'Cuenta', role: 'Rol', administrator: 'Administrador', viewer: 'Solo lectura', expires: 'La sesión caduca', logout: 'Cerrar sesión' },
  pt: { preferences: 'Preferências', account: 'Conta', role: 'Função', administrator: 'Administrador', viewer: 'Somente leitura', expires: 'A sessão expira', logout: 'Sair' },
};
