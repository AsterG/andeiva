import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.js';
import './styles.css';
import './firewall/firewall.css';
import './firewall/console.css';
import './routing/dhcp.css';

const container = document.getElementById('root');
if (container) {
  createRoot(container).render(<StrictMode><App /></StrictMode>);
}
