# SuckerPot design system

The UI is the product. The bar is a calm, precise SaaS dashboard (Linear, Vercel, Stripe). The anti-reference is T-Pot and Kibana: many panels, many colours, no story. Every decision below serves one goal: **someone glancing at the screen understands what attackers did, in plain English, in a few seconds.**

The source of truth is code: tokens in `src/styles/tokens.css`, Tailwind mapping in `src/styles/index.css`, components in `src/components/`. The `/styleguide` route shows all of it, in every state.

## Mood

Quiet, dark and precise, like an observatory at night. Neutral surfaces, hairline borders, generous space, and colour only where it means something. Motion is slow to start and fast to settle. Nothing blinks.

## Typography

| Role                                   | Font                                          | Notes                   |
| -------------------------------------- | --------------------------------------------- | ----------------------- |
| UI and text                            | Inter Variable (`@fontsource-variable/inter`) | Features `cv11`, `ss03` |
| Addresses, commands, hashes, URLs, IDs | JetBrains Mono Variable                       | Never for prose         |

- Self-hosted through `@fontsource`. No external font requests.
- `font-variant-numeric: tabular-nums` is set on `body`, so every number lines up and counters never jitter. Numbers use thousands separators (`formatNumber`, en-US).
- Scale (size / line height): `2xs` 11/16, `xs` 12/16, `sm` **13/20 (default UI)**, `base` 14/22 (card findings, page intros), `md` 16/24, `lg` 18/26, `xl` 22/28 (page titles), `2xl` 28/34 (KPI values), `3xl` 36/42.
- Weights: 400 body, 500 labels and findings, 600 titles and KPI values. Titles use `tracking-tight`.

## Colour

All colours are CSS variables on `:root` (dark, the default) and `[data-theme="light"]`. They are plain hex so `src/styles/contrast.test.ts` can check WCAG ratios for every pair. The theme follows the stored choice, else `prefers-color-scheme`, else dark. An inline script in `index.html` applies it before first paint.

### Neutrals

| Token                          | Dark                  | Light                 | Use                                    |
| ------------------------------ | --------------------- | --------------------- | -------------------------------------- |
| `--bg`                         | `#0b0c0e`             | `#f7f7f8`             | Page, sidebar                          |
| `--surface`                    | `#111215`             | `#ffffff`             | Cards                                  |
| `--surface-raised`             | `#17181c`             | `#ffffff`             | Popovers, selected segments            |
| `--surface-hover`              | `#1c1d22`             | `#f2f2f4`             | Hover, active nav                      |
| `--border` / `--border-strong` | `#23252a` / `#34373e` | `#e4e4e8` / `#d1d2d8` | Hairlines                              |
| `--fg`                         | `#ecedef`             | `#0f1013`             | Primary text                           |
| `--fg-muted`                   | `#a1a4ac`             | `#4f525a`             | Secondary text                         |
| `--fg-subtle`                  | `#858892`             | `#6a6d76`             | Labels, timestamps (still AA, ≥ 4.5:1) |

The primary action is neutral (`--primary` is the text colour, inverted). There is no brand hue: a hue always means a sensor or a severity.

### Sensors: one hue each

Picked from the Okabe–Ito colour-blind-safe family (sky blue, bluish green, reddish purple, ochre), and **always** paired with an icon and a label.

| Sensor | Icon            | Dark      | Light     |
| ------ | --------------- | --------- | --------- |
| SSH    | square terminal | `#5ea6f7` | `#1c6bc9` |
| Telnet | router          | `#3cc6a4` | `#0a7a62` |
| Web    | globe           | `#d98bcb` | `#a6458f` |
| RDP    | monitor         | `#e0b341` | `#8a6100` |

Each hue is AA (≥ 4.5:1) as text on `--bg`, `--surface` and its own tinted badge background (`tint-*` utilities: 14 % in dark, 10 % in light).

### Severity

| Level   | Meaning                                        | Icon          | Dark      | Light     |
| ------- | ---------------------------------------------- | ------------- | --------- | --------- |
| info    | Connected or probed                            | info          | `#a1a4ac` | `#4f525a` |
| notice  | Tried credentials or sent requests             | dot in circle | `#ecedef` | `#0f1013` |
| warning | Got a shell or ran commands                    | triangle      | `#f0883e` | `#b54708` |
| severe  | Download attempt, malware tag, exploit payload | octagon       | `#f2555a` | `#c8242b` |

**Red is reserved for severe.** Tags that mean a payload (`php2shell`, `crypto-miner`, `mirai`, `malware-drop`) get a small red diamond; all other tags are neutral. Deltas on KPIs are never green or red: for a honeypot, "more" is neither good nor bad, so they use an arrow and words.

No decorative gradients. The only fills under lines are flat, 8 % opacity.

## Space, shape, elevation

- 4 px grid. Page gutters: 16 px on mobile, 24 px on tablet, 40 px on desktop. Content max width 1200 px. Cards pad 16 px (mobile) / 20 px. Sections are separated by 24 px or more.
- Radius: 4 px chips, 6 px controls, 8 px small cards and nav items, 12 px cards. Pills are fully rounded only for the sensor share bar.
- Elevation: in dark, a border plus a faint top highlight (`--shadow-sm`); shadows only for overlays. In light, a soft 1–2 px shadow.

## Motion

- 150 ms (hover), 200 ms (fades), 250 ms (slide-in), all `cubic-bezier(0.22, 1, 0.36, 1)` (ease-out).
- New feed items slide in 6 px from above (`animate-slide-in`). Numbers tween over 600 ms (`AnimatedNumber`). The live dot pulses slowly (2.4 s).
- `prefers-reduced-motion: reduce` turns every animation and transition off; tweens jump to the final value.

## Content rules

- **A sentence before a chart.** `FindingCard` has a mandatory `finding` prop: the plain-English claim the chart proves. Page headers carry one sentence too ("380 sessions from 265 addresses in the last 24 hours.").
- **Stories, not rows.** A session reads as `describeSession()` writes it: "203.0.113.9 tried 37 SSH passwords, then ran 5 commands and tried to download 1 file". The function is pure and unit-tested (`src/lib/describe-session.test.ts`).
- **Everything clickable.** IPs, tags and sensor counts link to the filtered Attacks view. Filters live in the URL (`?sensor=ssh&src_ip=…`).
- **Times** are stored in UTC, shown relative ("5 min. ago") with the absolute time and the browser time zone on hover.
- **Long runs fold.** Repeated login attempts or HTTP requests in a timeline collapse into "Show 89 more login attempts · 2 min 9 s". Commands never fold: they are the story.
- **Empty and loading states** keep the final layout (skeletons have the same footprint) and say what is missing and what to do.

## Screenshot mode

"Mask IPs" in the sidebar footer, or `?mask=1` / `?mask=0` on any URL (persisted per browser), masks every address: `203.0.113.42` becomes `203.0.x.x`, and IPv4 addresses inside free text (URLs, commands, live summaries, the IP filter chip and page headlines) are masked the same way. Copy buttons are hidden while masked. Use it for any screenshot of real data.

## Which red, where

- A session is severe when it downloaded something or carries a payload tag (`sessionSeverity`).
- A single event gets the red icon only when the event itself is severe (`isSevereEvent`): a download attempt, or an HTTP request tagged as an exploit (`php2shell`). A failed login in a session tagged `malware-drop` stays neutral; the red-marked tag badge already says it.

## Terminal replay

The replay terminal is always dark, in both themes, with its own muted ANSI palette (`src/components/replay/terminal-theme.ts`). Attacker-controlled colours never reuse a sensor hue or the "severe" red: an attacker printing red text must not look like a SuckerPot alert. Every ANSI colour is AA on the terminal background (tested). Replays keep at least 80 columns; on narrow screens the terminal scrolls sideways instead of re-wrapping the output. In screenshot mode the terminal masks addresses while keeping their length (`198.51.xxx.xx`), so columns stay aligned.

## KPI tiles

Every tile has the same structure: label, value, one footer line pinned to the bottom. The footer shows a neutral delta when a previous window exists, otherwise a plain hint. No sparkline in the Overview KPIs: the activity chart right below already shows the series.

## Bars and shares

Bars that stand for a sensor use that sensor's colour (the stacked activity chart, the sensor share bar). Every other bar is neutral: the share bars in top lists, an attacker's activity per day (an attacker spans sensors). Tinted backgrounds use the `tint-*` utilities only.

## Tags over time

Only one tag is red: the leading payload tag, which is what the card's finding sentence is about. Every other tag, payload or not, is a neutral lightness step, and payload tags keep a red-outlined diamond in the legend and tooltip. This keeps red rare even when most tagged traffic is malicious.

## Heatmap

Day × hour uses a five-step neutral scale (color-mix of `--fg` into `--surface`), a "Fewer … More" key, and a readout line for the hovered or tapped cell. Hours are shown in the browser time zone.

## Globe

Arcs use the sensor hues, fly once and vanish; a soft ring marks the landing. Arcs shorter than 4° (an attack from the home country) or near-antipodal ones are not drawn as arcs, only as a ring pulse, and arc height is proportional to distance and clamped low (0.04–0.18 globe radii) so arcs heading to the far side do not read as spikes at the limb, so nothing spikes. The globe pauses when hidden or off screen, and reduced motion shows a still view with the latest origins. three.js makes the globe chunk large (about 490 kB gzip); it loads only on the Live page.

## Settings

Read-only by design: a dashed note says settings live in `.env`. Four cards, each with a finding sentence: Sensors (Active / Quiet / Silent with icon and label; silent is a warning, never red), Enrichment (GeoIP provider, age, the required attribution text, quota meters), Data retention, Storage (database against its ceiling; red only when the disk guard is critical).

## Loading

Heavy pages (Overview, Live, Attackers, attacker profile, session detail, styleguide) load on demand behind a `PageSkeleton` in the final layout. Recharts and xterm get their own chunks, so the first load stays small.

## Scrolling

Lists scroll with the window (Attacks), except the Live feed: it is a "leave it running" screen whose hold-to-read and "N new events" logic need their own scroll area. It fills the viewport height, so there is never a scroll area inside a short box.

## Components

| Component                  | File                                     | Notes                                                                                                                                           |
| -------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| FindingCard ("Card")       | `finding-card.tsx`                       | eyebrow + finding sentence + optional detail, action, footer                                                                                    |
| StatTile                   | `stat-tile.tsx`                          | label, tweened value, neutral delta or hint, sparkline slot, loading                                                                            |
| Sparkline                  | `sparkline.tsx`                          | tiny line, flat 8 % area, accessible label                                                                                                      |
| SensorShare                | `sensor-share.tsx`                       | stacked bar + labelled legend, links to filtered list                                                                                           |
| SensorBadge                | `sensor-badge.tsx`                       | `badge` (tint + icon + label) or `dot`                                                                                                          |
| SeverityBadge              | `severity-badge.tsx`                     | icon + label, or icon only with an accessible name                                                                                              |
| TagBadge                   | `tag-badge.tsx`                          | mono, neutral; red diamond for payload tags                                                                                                     |
| IPChip                     | `ip-chip.tsx`                            | mono, copy button, links to `?src_ip=`, `masked`, `chip` or `ghost`                                                                             |
| CountryFlag                | `country-flag.tsx`                       | SVG flag (`country-flag-icons`, one small asset each) + name tooltip, `?` for unknown                                                           |
| RelativeTime               | `relative-time.tsx`                      | shared 30 s clock, absolute time tooltip                                                                                                        |
| EventRow                   | `event-row.tsx`                          | icon per event type, mono details, red only for downloads, optional sensor accent                                                               |
| EventTimeline              | `event-timeline.tsx`                     | EventRows with folded runs                                                                                                                      |
| SessionStory               | `session-story.tsx`                      | IP chip + flag + origin + predicate, `inline` or `block`                                                                                        |
| SessionRow                 | `session-row.tsx`                        | one line on desktop, two on mobile, stretched link                                                                                              |
| FilterBar, SensorFilter    | `filter-bar.tsx`                         | URL-synced segmented control and removable chips                                                                                                |
| PageHeader                 | `page-header.tsx`                        | title + one sentence + actions                                                                                                                  |
| EmptyState                 | `empty-state.tsx`                        | icon, optional "Coming in Mx" badge, text, action                                                                                               |
| Skeletons                  | `skeletons.tsx`                          | text, row, list, tile, card                                                                                                                     |
| LiveEventRow               | `live-event-row.tsx`                     | one live event: sensor badge, summary (text only), tags, IP, flag, time; whole row opens the session                                            |
| LiveSensorTile             | `live-sensor-tile.tsx`                   | events in the last minute for one sensor, in its hue, links to filtered Attacks                                                                 |
| LatestEventsCard           | `latest-events-card.tsx`                 | FindingCard with the newest live events (Overview)                                                                                              |
| SensorActivityChart        | `charts/sensor-activity-chart.tsx`       | Recharts stacked bars (events per hour, fixed sensor order, sensor hues), legend with icons + totals linking to filtered Attacks, sr-only table |
| DayBars                    | `charts/day-bars.tsx`                    | 30 neutral daily bars for one attacker, sr-only table                                                                                           |
| TopList                    | `top-list.tsx`                           | ranked rows with printed count + share (bar is decoration), each row a filtered link                                                            |
| AttackerRow                | `attacker-row.tsx`                       | one-line attacker profile story; row opens the profile, chips/flags/tags open filtered lists                                                    |
| LiveIndicator, ThemeToggle | `live-indicator.tsx`, `theme-toggle.tsx` | shell chrome                                                                                                                                    |

Primitives (button, card, badge, tooltip, dropdown-menu, sheet, separator, skeleton, scroll-area, tabs, toggle, toggle-group, command, dialog, popover, input) come from shadcn/ui via the CLI and live in `src/components/ui/`. They read our tokens through the shadcn variable contract mapped in `index.css`. Do not edit them for one page: add a variant here instead.
