# Theme audit

Baseline: `aca5f82`, before the centralized Design System changes. The inspected
interface was a development page, not a firewall administration application.
This audit covers its source, theme preferences, branding and existing tests.

## Findings and causes

| Finding | Baseline evidence | Cause and required correction |
| --- | --- | --- |
| A large light region dominates Dark | `.brand-panel` has `background: #ffffff`; `.brand-image` allows a width of `51rem` | The approved raster already contains a light background. Keeping that background is correct; presenting it as a large generic surface is visually inconsistent. Use a compact, explicit branding surface and preserve the complete image. |
| Theme scope stops at the application wrapper | `App.tsx` sets `data-theme` on `.app` | Document backgrounds and future elements rendered outside that wrapper do not inherit its variables. Apply the theme and semantic tokens at the document root. |
| The token vocabulary is incomplete | `styles.css` defines seven variables; Dark replaces five | A small page can reuse a single surface, but future controls, overlays, charts and states need distinct semantic contracts. Define both themes completely and reject missing tokens. |
| Initial document appearance is not restored before rendering | `index.html` declares a light color scheme; the saved preference is read when React renders | A saved Dark preference can disagree with the initial document. Restore the validated preference before the application and styles paint. Light remains the fallback. |
| Decorative and interactive borders share one color | Selects and content panels both use `--border` | A soft divider is not necessarily a visible control boundary. Separate decorative borders from control, focus and selected-state indicators. |
| Layout values have no shared scale | Spacing, radii and typography are repeated in page CSS | Future modules can drift even when their colors match. Define shared scales and consume reusable components. |
| Validation cannot detect visual regressions | Existing tests inspect server-rendered markup, preferences and the logo digest | These checks cannot establish computed styles, actual keyboard behavior, responsive layout or visual consistency. Add browser checks and reviewed screenshot baselines for both themes. |

The baseline contained no tables, modals, menus or charts. This audit does not
attribute existing defects to components that had not been implemented. It also
found no existing shadow system to evaluate; shadow tokens are a new contract.

## Contrast constraints

The approved palette remains the brand palette. Interactive and status colors
may use documented derivatives when the original accent does not provide enough
contrast for its specific use.

| Pair | Calculated ratio | Consequence |
| --- | --- | --- |
| White on electric blue `#087CF5` | 4.03:1 | Insufficient for normal-size text; do not assume a brand accent is a valid button background. |
| Navy `#061B4B` on electric blue `#087CF5` | 4.12:1 | Also insufficient for normal-size text. |
| White on the blue derivative `#0562C7` | 5.87:1 | An example of a suitable normal-text action pairing; the implemented token pairs must still be tested. |
| Soft border `#D8E6F3` against white | 1.27:1 | Suitable for decoration, not the sole essential boundary of an otherwise indistinguishable control. |
| Old Dark border `#42556C` against surface `#142338` | 2.07:1 | Does not reach 3:1 if that boundary is necessary to identify the control. |

Ratios above use the WCAG relative-luminance formula and are rounded only for
display. Tests must compare the unrounded value. Normal text requires 4.5:1;
large text has a 3:1 threshold. Essential non-text visual information requires
3:1 against adjacent colors. Labels, shapes and patterns must supplement color
where color alone would convey state. See the W3C explanations for
[text contrast](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html)
and [non-text contrast](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html).

## Required regression coverage

- A fresh visit remains Light when the operating system prefers Dark.
- Manual Dark selection persists; invalid or unavailable storage falls back
  safely without preventing theme selection in the current page.
- The saved theme is applied before the application renders, including the
  document background and overlays.
- Both themes define the complete semantic token inventory. Component and page
  styles contain no independent color palettes.
- Text, controls, selected states, focus indicators and status combinations are
  checked in both themes. Native browser controls are also inspected in-browser.
- Desktop, tablet and mobile layouts remain usable; keyboard focus is visible,
  dialogs close and restore focus, and EN/ES/PT content retains its meaning.
- Real screenshot comparisons cover the page, reusable components and overlays
  without masking the themed areas.
- The approved logo retains its SHA-256 digest, proportions and complete content;
  no filter, recoloring or crop is applied.

Source inspection and automated accessibility checks do not constitute a complete
WCAG conformance assessment. Browser versions, viewports, test results and any
manual assistive-technology limitations must accompany the implementation review.
Do not describe a planned check as an executed result.

## Maintenance rule

Every new module uses the shared tokens and components. Any new visual state must
be represented and tested in both themes before integration. This applies equally
to firewall, NAT, VPN, SD-WAN, QoS, security profiles, inspection modules, DNS,
logs, PCAP, administration, transactional configuration and system maintenance.
The component examples demonstrate appearance and interaction only; they do not
represent implemented network capabilities or live appliance measurements.
