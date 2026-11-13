export function ConsoleIcon({ name }: { name: string }) {
  const paths: Record<string, string> = {
    dashboard: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
    rules: 'M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4ZM8 12l3 3 5-6',
    audit: 'M5 3h14v18H5zM8 7h8M8 11h8M8 15h5',
    configuration: 'M3 6h18M3 12h18M3 18h18M7 3v6M16 9v6M10 15v6',
    traffic: 'M3 18h18M5 14V9M10 14V4M15 14v-3M20 14V6',
    system: 'M4 4h16v6H4zM4 14h16v6H4zM7 7h.01M7 17h.01M11 7h6M11 17h6',
    menu: 'M4 6h16M4 12h16M4 18h16',
    network: 'M9 3h6v6H9zM2 16h6v5H2zM16 16h6v5h-6zM12 9v4M5 16v-3h14v3',
    nat: 'M3 8h16l-4-4M21 16H5l4 4',
  };
  return <svg className="console-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] ?? paths.rules} /></svg>;
}
