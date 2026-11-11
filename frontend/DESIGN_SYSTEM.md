# ANDEIVA interface system

All current and future management modules share this system. Firewall, NAT, VPN,
SD-WAN, QoS, security profiles, inspection, DNS, logs, PCAP, administration,
transactional configuration and system pages must not introduce independent
palettes. The current administrative console exposes only operations supported by its authenticated runtime; future engines remain unavailable.

The component library at `/?view=design-system` contains local interface examples. The root URL and `/firewall` open the authenticated console. See [EN](docs/console-en.md), [ES](docs/console-es.md) and [PT](docs/console-pt.md). Its rows, states and
form actions are demonstrations, not appliance observations or configuration.

## Theme ownership

`src/design-system/tokens.css` is the single source of visual tokens. It defines
Light on `:root` and a complete color override on `:root[data-theme="dark"]`.
Components consume semantic variables rather than literal colors. Theme state
belongs on the document element so dialogs and future portals inherit it.

`public/theme-init.js` runs synchronously in the document head before application
content. Only the stored value `dark` selects Dark; missing, invalid or inaccessible
storage selects Light. The key remains `andeiva.preview.theme`. Neither bootstrap
nor React reads operating-system color preferences. The selector applies the new
theme immediately, then saves it; storage failure does not disable the selection.

Use `applyTheme`, `readTheme`, `parseTheme` and `saveTheme` from `preferences.ts`.
Do not add per-screen theme state, `prefers-color-scheme` switching or color filters.
The bootstrap key and accepted values must stay aligned with those functions.

## Semantic tokens

| Purpose | Tokens |
| --- | --- |
| Layout | `--color-background`, `--color-surface`, `--color-surface-elevated`, `--color-header`, `--color-sidebar` |
| Text | `--color-text`, `--color-text-secondary`, `--color-link` |
| Edges and focus | `--color-border`, `--color-border-control`, `--color-focus` |
| Actions | `--color-button-primary`, `--color-button-primary-hover`, `--color-button-primary-text`, secondary equivalents |
| Fields | `--color-input`, `--color-input-text`, `--color-input-placeholder` |
| Navigation and tables | `--color-nav-*`, `--color-table-header`, `--color-table-hover`, `--color-table-selected` |
| Overlays | `--color-modal`, `--color-menu`, `--color-tooltip`, `--color-tooltip-text`, `--color-backdrop` |
| Feedback | `--color-notification`, `--color-{success,warning,error,info}-{bg,text}` |
| Charts | `--color-chart-1` through `--color-chart-4`, `--color-chart-grid`, `--color-chart-legend` |
| Geometry | `--space-*`, `--radius-*`, `--control-min-height` |
| Type and depth | `--font-*`, `--text-*`, `--line-*`, `--weight-*`, `--shadow-*` |

The approved electric blue and cyan remain brand accents. Primary buttons use a
darker derived blue in Light because white normal-size text on the approved
electric blue does not meet a 4.5:1 contrast ratio. Dark uses a light derived blue
with dark text. Soft borders separate surfaces; stronger control borders identify
interactive boundaries. Do not substitute decorative border tokens for fields.

State text also provides its icon and invalid-field border color. A selected row
retains a checked control, and status badges include symbols and words. Chart
legends demonstrate line patterns as well as colors; a future graph must carry
the same patterns into its plotted series and provide an accessible data summary.

## Approved logo

`public/andeiva-logo.png` is unchanged. Its SHA-256 is
`1f79f5ec7f33327c9285c702b63fc5c5a618a28395b2161d594001fdb0199f81`.

The raster artwork contains a light background. A compact branding surface uses
`--color-brand-surface` and `--color-brand-border`, deliberately identical in both
themes. This is the only permanent light visual region in Dark. It is not a generic
card style. Use the original image with preserved aspect ratio and `object-fit:
contain`. Never crop, redraw, recolor, stretch or apply CSS filters. A separate
dark artwork variant would require explicit approval.

## Components and accessibility

Import shared primitives from `src/design-system/components.tsx`:

- `Button`: primary or secondary, native disabled and submit semantics.
- `Surface`: labeled section with a heading and optional description.
- `Field` and `TextInput`: visible labels and a common input surface. Connect
  hint/error IDs with `aria-describedby`; invalid inputs need `aria-invalid`.
- `FilterBar`: labeled search region. Filter controls retain independent labels.
- `DataTable`: caption, named scroll region and keyboard-accessible overflow.
  Supply native column/row headers with `scope`; do not replace tables with grids.
- `StatusBadge` and `Notice`: text and symbols accompany color. Use `Notice live`
  only for a new action result, not static page descriptions.
- `Navigation`: labeled native navigation with `aria-current` on the selected view.
- `Dialog`: native modal dialog, visible title, Escape/Close, contained Tab focus
  and browser focus restoration. Every action requires a visible text label.
- `HelpTip`: keyboard and pointer help, Escape dismissal, hover persistence.
- `Legend`: visible labels and distinct line patterns for future graphs.

The disclosure example uses native `details`/`summary`; it does not pretend to be
an ARIA menu without implementing a menu keyboard model. Selects and textareas
use `ds-select` and `ds-textarea` within `Field`. Keep labels and descriptions in
`messages.ts`; all keys must exist in English, Spanish and Portuguese. English is
the application default. Keyboard focus must remain visible in both themes.

## Adding a module

1. Compose the existing shell and primitives. Add a semantic token only when a
   new role cannot be represented by an existing one; define it in both themes.
2. Keep domain behavior outside visual primitives. No component may bypass the
   future shared backend authorization or introduce a privileged command path.
3. Add localized copy and meaningful empty, loading, error and selected states.
4. Test Light and Dark at desktop, tablet and mobile widths, including 200% text
   scaling, keyboard navigation, dialog focus and long translated strings.
5. Check text contrast at 4.5:1 (3:1 for qualifying large text) and meaningful
   non-text control/focus contrast at 3:1. Automated accessibility tools are a
   gate, not a certification or a substitute for assistive-technology review.
6. Add or review visual snapshots for every affected view in both themes.

Run the source checks with Node 24:

```bash
npm --prefix frontend ci --ignore-scripts --no-audit --no-fund
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
```

Use the canonical browser environment for accessibility, interaction and screenshot
comparisons:

```bash
docker build -f frontend/Dockerfile.visual -t andeiva-design-check .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check
```

The Dockerfile pins Playwright 1.65.0 on Linux Noble and Node 24.20.0 by image
digest. Node and its bundled npm/npx 11.19.0 share an isolated toolchain directory;
the build checks executable destinations and prints all three versions. Search
uses locale-independent casing, tested with a Turkish browser locale and EN/ES/PT
interface text; it does not remove accents. CI builds the same environment. The test server needs no backend, host
port or access to the network laboratory. Image/dependency downloads occur during
build when missing from the cache; test execution has no external network.

When a visual change is intentional, generate references in that environment:

```bash
docker create --name andeiva-design-baselines --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check npm run test:visual:update
docker start --attach andeiva-design-baselines
docker cp andeiva-design-baselines:/work/frontend/e2e/snapshots frontend/e2e/
docker rm andeiva-design-baselines
```

Use an available container name and copy references only after successful
generation. Review every changed image, then rebuild the image and repeat the
normal comparison so it includes the new references. Never automatically replace
baselines to silence a failing CI check or mask themed surfaces. Passing only one
theme is insufficient. Browser checks inspect accessible semantics; they must not
be represented as a real screen-reader session unless one was actually performed.

See the [audit](DESIGN_AUDIT.md), [Spanish guide](docs/design-system-es.md) and
[Portuguese guide](docs/design-system-pt.md). Pull requests record verification
results and remaining limitations alongside the automated check results.
