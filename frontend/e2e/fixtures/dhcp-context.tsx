// Test-only component host. External events represent immutable server/context updates.
// It is bundled in memory by Playwright, never included in a product entry point.
import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { DHCPSettings } from '../../src/routing/DHCPSettings.js';
import type { ConfigurationCurrent, RoutedConfig } from '../../src/routing/configuration.js';
import type { DHCPScope } from '../../src/routing/dhcp.js';
import fixtures from '../../tests/fixtures/routed-current-v2.json';
import '../../src/styles.css';
import '../../src/firewall/firewall.css';
import '../../src/routing/dhcp.css';

const context = structuredClone(fixtures.routed.current) as ConfigurationCurrent;
const draft = structuredClone(context.snapshot.running.config) as RoutedConfig;
const scope = (id: string, iface: string, subnet: string): DHCPScope => ({ id, interface_id: iface, subnet: `${subnet}.0/24`, router: `${subnet}.1`, pools: [{ first: `${subnet}.10`, last: `${subnet}.30` }], excluded: [], reservations: [], dns: [], ntp: [], domain: '', lease_seconds: 3600, renew_seconds: 1800, rebind_seconds: 3150 });
draft.routed = { ...draft.routed, schema_version: 2, dhcp_server: { schema_version: 1, enabled: false, scopes: [scope('alpha', 'lan', '198.18.0'), scope('beta', 'lan-two', '198.20.0')] } };
draft.routed.network.config.interfaces.push({ id: 'lan-two', binding: { name: 'lan2', hardware_address: '02:00:00:00:03:01' }, role: 'lan', zone: 'inside', ipv4: { mode: 'static', address: '198.20.0.1/24' } });

function Host() {
  const [selected, setSelected] = useState(draft), [source, setSource] = useState(context);
  const [editing, setEditing] = useState(false), [admin, setAdmin] = useState(true), [editable, setEditable] = useState(true), [visible, setVisible] = useState(true);
  const [writes, setWrites] = useState(0);
  useEffect(() => {
    const update = (event: Event) => {
      const kind = (event as CustomEvent<string>).detail;
      if (kind === 'reordered-response') {
        const next = structuredClone(draft);
        next.routed.dhcp_server!.scopes.reverse(); next.routed.dhcp_server!.scopes[1]!.domain = 'external.example';
        setSelected(next); setSource(structuredClone(context));
      } else if (kind === 'snapshot') setSource(structuredClone(context));
      else if (kind === 'generation') setSource({ ...context, global: { ...context.global, generation: '12' } });
      else if (kind === 'draft-reset') setSelected(structuredClone(draft));
      else if (kind === 'network') { const next = structuredClone(draft); next.routed.network.config.interfaces[0]!.ipv4.address = '198.18.0.2/24'; setSelected(next); }
      else if (kind === 'readonly') setAdmin(false);
      else if (kind === 'blocked') setEditable(false);
      else if (kind === 'logout') setVisible(false);
    };
    window.addEventListener('fixture-context-update', update);
    return () => window.removeEventListener('fixture-context-update', update);
  }, []);
  return <main><output data-testid="writes">{writes}</output><output data-testid="editing">{String(editing)}</output><output data-testid="draft">{JSON.stringify(selected.routed.dhcp_server)}</output>{visible && <DHCPSettings locale="en" current={selected} context={source} admin={admin} editable={editable} editing={editing} onEditing={setEditing} onChange={(next) => { setSelected(next); setWrites((n) => n + 1); }} />}</main>;
}
createRoot(document.getElementById('root')!).render(<Host />);
