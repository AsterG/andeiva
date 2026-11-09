export type Locale = 'en' | 'es' | 'pt';

interface Messages {
  language: string;
  theme: string;
  light: string;
  dark: string;
  phase: string;
  title: string;
  description: string;
  limitation: string;
}

export const messages: Record<Locale, Messages> = {
  en: {
    language: 'Language',
    theme: 'Appearance',
    light: 'Light',
    dark: 'Dark',
    phase: 'Development preview',
    title: 'The foundation starts here.',
    description: 'ANDEIVA Security Gateway is under development.',
    limitation: 'This page does not manage or protect network traffic.',
  },
  es: {
    language: 'Idioma',
    theme: 'Apariencia',
    light: 'Claro',
    dark: 'Oscuro',
    phase: 'Vista previa de desarrollo',
    title: 'La base comienza aquí.',
    description: 'ANDEIVA Security Gateway está en desarrollo.',
    limitation: 'Esta página no administra ni protege el tráfico de red.',
  },
  pt: {
    language: 'Idioma',
    theme: 'Aparência',
    light: 'Claro',
    dark: 'Escuro',
    phase: 'Prévia de desenvolvimento',
    title: 'A base começa aqui.',
    description: 'ANDEIVA Security Gateway está em desenvolvimento.',
    limitation: 'Esta página não administra nem protege o tráfego de rede.',
  },
};

export function parseLocale(value: string): Locale {
  return value === 'es' || value === 'pt' ? value : 'en';
}
