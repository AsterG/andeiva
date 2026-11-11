import type { Locale } from '../messages.js';
import { Button } from './components.js';
import { HeaderPopover } from './HeaderPopover.js';
import { headerMessages } from './headerMessages.js';

export function HeaderAccount({ locale, username, role, expiresAt, busy, logout }: { locale: Locale; username: string; role: 'admin' | 'viewer'; expiresAt: string; busy: boolean; logout: () => void }) {
  const copy = headerMessages[locale];
  return <HeaderPopover name="account" label={`${copy.account}: ${username}`} className="ds-header-account" icon={<><span className="ds-header-avatar" aria-hidden="true">{username.slice(0, 1).toUpperCase()}</span><span className="ds-header-name">{username}</span><svg className="ds-header-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><path d="m7 10 5 5 5-5" /></svg></>}>
    <h2>{copy.account}</h2><p className="ds-header-username">{username}</p>
    <dl><div><dt>{copy.role}</dt><dd>{role === 'admin' ? copy.administrator : copy.viewer}</dd></div><div><dt>{copy.expires}</dt><dd><time dateTime={expiresAt}>{new Date(expiresAt).toLocaleString(locale)}</time></dd></div></dl>
    <Button variant="secondary" disabled={busy} onClick={logout}>{copy.logout}</Button>
  </HeaderPopover>;
}
