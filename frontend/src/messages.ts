export type Locale = 'en' | 'es' | 'pt';

interface Messages {
  language: string;
  theme: string;
  light: string;
  dark: string;
  phase: string;
  title: string;
  description: string;
  scope: string;
  limitation: string;
}

export const messages: Record<Locale, Messages> = {
  en: {
    language: 'Language',
    theme: 'Appearance',
    light: 'Light',
    dark: 'Dark',
    phase: 'Development preview',
    title: 'Development foundation',
    description: 'ANDEIVA Security Gateway is under development.',
    scope: 'Phase 0 · Current scope',
    limitation: 'This page does not manage or protect network traffic.',
  },
  es: {
    language: 'Idioma',
    theme: 'Apariencia',
    light: 'Claro',
    dark: 'Oscuro',
    phase: 'Vista previa de desarrollo',
    title: 'Base de desarrollo',
    description: 'ANDEIVA Security Gateway está en desarrollo.',
    scope: 'Fase 0 · Alcance actual',
    limitation: 'Esta página no administra ni protege el tráfico de red.',
  },
  pt: {
    language: 'Idioma',
    theme: 'Aparência',
    light: 'Claro',
    dark: 'Escuro',
    phase: 'Prévia de desenvolvimento',
    title: 'Base de desenvolvimento',
    description: 'ANDEIVA Security Gateway está em desenvolvimento.',
    scope: 'Fase 0 · Escopo atual',
    limitation: 'Esta página não administra nem protege o tráfego de rede.',
  },
};

export function parseLocale(value: string): Locale {
  return value === 'es' || value === 'pt' ? value : 'en';
}
