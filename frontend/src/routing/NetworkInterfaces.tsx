import { useEffect, useState } from 'react';
import { Button, DataTable, Notice, StatusBadge, Surface } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import { configurationRequest } from '../firewall/api.js';
import { networkInventoryResponse } from './inventory.js';
import type { NetworkInventory } from './inventory.js';
import { routingMessages } from './messages.js';

export function NetworkInterfaces({ locale }: { locale: Locale }) {
  const copy = routingMessages[locale];
  const [state, setState] = useState<{ loading: boolean; inventory: NetworkInventory | null }>({ loading: true, inventory: null });
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setState({ loading: true, inventory: null });
    void configurationRequest<unknown>('network/interfaces', undefined, undefined, controller.signal).then((data) => {
      if (active) setState({ loading: false, inventory: networkInventoryResponse(data) });
    }).catch(() => {
      if (active) setState({ loading: false, inventory: null });
    });
    return () => { active = false; controller.abort(); };
  }, [refresh]);
  return <Surface title={copy.title} description={copy.intro}>
    <div className="ds-actions"><Button variant="secondary" disabled={state.loading} onClick={() => setRefresh((value) => value + 1)}>{copy.refresh}</Button></div>
    <div aria-busy={state.loading} aria-live="polite">
      {state.loading ? <p>{copy.loading}</p> : !state.inventory ? <Notice title={copy.unavailable}>{copy.unavailableHint}</Notice> : state.inventory.interfaces.length === 0 ? <p>{copy.empty}</p> : <DataTable caption={copy.title}>
        <thead><tr><th scope="col">{copy.interface}</th><th scope="col">{copy.address}</th><th scope="col">{copy.mac}</th><th scope="col">{copy.mtu}</th><th scope="col">{copy.state}</th></tr></thead>
        <tbody>{state.inventory.interfaces.map((iface) => <tr key={iface.name}>
          <th scope="row">{iface.name}</th>
          <td>{iface.addresses.length ? <ul>{iface.addresses.map((entry) => <li key={`${entry.ip}/${entry.prefix}`}>{entry.prefix ?? entry.ip}</li>)}</ul> : copy.none}</td>
          <td>{iface.hardware_address || copy.none}</td><td>{iface.mtu}</td>
          <td><StatusBadge tone={iface.admin_up ? 'success' : 'info'}>{iface.admin_up ? copy.up : copy.down}</StatusBadge><p className="fw-meta">{iface.running ? copy.running : copy.inactive}</p></td>
        </tr>)}</tbody>
      </DataTable>}
    </div>
    <p className="fw-meta">{copy.hint}</p>
  </Surface>;
}
