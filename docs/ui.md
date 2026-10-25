# Dashboard

The dashboard is a single-page web app in `web/`. The API serves the built files, so there is one port to publish and one thing to put behind the tunnel. The design rules are in `web/DESIGN.md`. Colour tokens, the type scale and every component are shown on the `/styleguide` page of a running dashboard.

```{admonition} Build status
:class: note

**Built:** the app shell, the design system, the login page, **Live** (feed), **Overview** (with insights), **Attacks**, **Session detail**, **Attackers** (list and profile), **Trends** and **Malware**.

**In progress:** the terminal replay (M5).

The pages read the endpoints described in [API](api.md).
```

## Principles

- **A sentence before a chart.** Every card opens with a plain-English finding, then shows the evidence.
- **Colour means something.** One hue per sensor family (remote shells blue, web and APIs purple, databases green, Windows and VoIP ochre), always paired with an icon and a label. Each sensor has its own icon and name. Red is reserved for severe events: a download attempt, or an exploit or malware tag.
- **Everything is clickable.** An address, a tag or a sensor count opens the matching filtered view. Filters live in the URL, so every view can be shared.
- **Calm real-time.** New events slide in softly, numbers tween, nothing flashes. With "reduce motion" set in the system, all animation is off.
- **Times** are stored in UTC and shown in the browser's time zone, relative ("5 min. ago") with the exact time on hover.
- **Dark by default**, with a light theme. The theme follows the stored choice, then the system setting.

## Pages

| Page | Path | Status | What it shows |
| --- | --- | --- | --- |
| Sign in | `/login` | Built | The login form. Any other page sends you here when there is no session. |
| Today | `/` | Built | The home page: three to five cards, each one plain-English sentence, up to three items that open a filtered view, and one action. What happened in 24 hours, new campaigns, what to block now, what is new this week, and (once a service inventory exists) your exposure. See [Today, search and the glossary](#today-search-and-the-glossary). |
| Live | `/live` | Built | A flat world map of the last 15 minutes of attacks, with arcs landing at the home point, a stats strip, a ticker of the newest events and rankings of addresses, countries and networks. See [The Live page](#the-live-page). |
| Overview | `/overview` | Built | KPIs for the last 24 hours, activity per sensor, the sensor mix, the latest events and up to three insights (see below). |
| Attacks | `/attacks` | Built | Sessions, newest first, one line each, as a short story. Filters: sensor, source address and period in the app today. The API also filters by tag, country and network. Pages of 50, virtualised. |
| Session detail | `/attacks/<session id>` | Built (replay in progress) | The attack timeline, with long runs of the same event folded, and a source panel. |
| Attackers | `/attackers`, `/attackers/<ip>` | Built | Profiles by address and by network: first and last seen, sensors targeted, reputation. |
| Trends | `/trends` | Built | Top usernames, passwords, commands and URLs, tags over time, a day by hour heatmap, and "new this week" (values never seen in the 90 days before). |
| Infrastructure | `/infrastructure` | Built | A finding first ("40 scanning IPs fetched payloads from 2 shared hosts this week"), a flow diagram from source addresses through indicators to malware families (a list on narrow screens), a filterable indicator table, a detail panel with threat-intelligence answers, and CSV or STIX 2.1 export buttons. Indicators are defanged text, never links. |
| Malware | `/malware` | Built | Download URLs, defanged, with how often, from how many addresses and with which tool. File hashes and VirusTotal links appear only if payload fetching exists, which it does not yet. |
| Settings | `/settings` | Built | Sensor status, enrichment quotas, retention, the disk guard and the database size. The enrichment API keys (AbuseIPDB, GreyNoise, MaxMind) can be set, replaced, removed and tested here: write-only, with a password prompt for every change (see [Enrichment keys in Settings](configuration.md#enrichment-keys-in-settings)). Administrators also see **Users** (add a person, change a role, disable, reset a password, unlock, sign out everywhere, delete) and the **Audit log**; viewers see neither, and no control that changes anything (see [Users and roles](#users-and-roles)). It uses `GET /api/v1/settings/system`, `/settings/enrichment`, `/settings/providers/{provider}`, `/users` and `/audit`. |
| Styleguide | `/styleguide` | Built | Every token and component, in every state. |

## Sign in

When the API answers `401`, the app shows the sign-in page. After a successful login the session lasts `SESSION_TTL_HOURS` (12 by default). The cookies are set by the server; the app never stores the password or a token in the browser's storage. The app reads the CSRF cookie and sends it on every write. Too many attempts show "Wait a minute, then try again". If login keeps failing behind a tunnel (the API answers `403` to a cross-origin login), add the public origin to `API_ALLOWED_ORIGINS` (see [Deployment](deployment.md#behind-a-tls-terminating-tunnel)).

## Users and roles

Two kinds of people can use the dashboard besides the owner: **administrators** and **viewers** (see [Users and roles](configuration.md#users-and-roles) for what each may do).

- **Add a user** (Settings > Users > Add user): username, name, role and your own password. The app then shows a temporary password **once**, in a dialog that does not close by accident, with a Copy button and a warning. The person signs in with it and is taken to **Set your password** before anything else.
- **Row actions** (the three dots): change role, disable or enable, unlock (only while locked), reset password (shows a new temporary password once), sign out everywhere, delete. Each asks for your own password. You cannot do the destructive ones to your own account.
- **Status** is one word with an icon: Active, Waiting for first sign-in, Locked, Disabled. The owner row says "Set in .env" and has no actions.
- **Audit log**: newest first, one sentence per entry ("sam reset the password of riley"), filterable by kind (Sign-ins, Users, Keys) and by name; the filters are in the URL (`?audit_action=user.&audit_actor=sam`). Click a name to filter by it.
- **Viewers** get the same pages, with a small "Read-only access" mark in the sidebar footer (and in the mobile header), no key buttons, and no Users or Audit cards.
- **Account menu** (sidebar footer): your name, role, last sign-in, **Change password** and **Sign out**. The owner's password is changed in `.env`, so that entry is disabled for the owner.

In the demo and mock builds, add `?as=viewer` to any address to preview the read-only interface and `?as=first-login` for the Set your password screen (`?as=admin` goes back). The choice lasts for the browser tab.

## Insights

The Overview page opens with up to three insights, each one a plain sentence with the numbers behind it, for example "PHP2Shell exploit attempts tripled since Tuesday (312 vs 104)." They come from fixed rules, not from a language model, and each rule has a minimum volume so a quiet host stays quiet. Each insight links to the filtered view that shows its evidence. The rules and thresholds are in [API](api.md#get-apiv1insights). Days in the wording are UTC days.

## Trends and malware

- **A sentence before a chart.** Every Trends card states what the chart shows ("Most attacks arrive between 02:00 and 05:00") before the chart.
- **Local time.** The heatmap is stored by UTC hour and shown in the browser's time zone.
- **Defanged URLs.** On the Malware page a URL is shown as `hxxp://example[.]com/x.sh`, as plain text and never as a link, so it cannot be opened by mistake. The copy button copies the defanged form. Do the same wherever you paste these URLs.
- **Nothing is fetched.** The page lists URLs that attackers tried to download. SuckerPot does not download them.

## Sessions as stories

A session row reads like a sentence, for example: "203.0.113.9 tried 37 SSH passwords, then ran 5 commands and tried to download 1 file". The text is written by one pure function in the app and covered by unit tests. The same words are used on the Attacks list, the Live feed and the Session page.

A session is marked severe when it downloaded something or carries a payload tag (such as `php2shell`, `crypto-miner`, `mirai` or `malware-drop`). A single event gets the red icon only when the event itself is severe.

## The Live page

The Live page is the screen to leave running on a wall or a second monitor. The map is the main element. There is no 3D globe: a flat map is easier to read at a glance, and it shows every source in its real place.

From top to bottom:

- **Map.** A flat world map (Equal Earth projection) with land and borders. It shows the last 15 minutes of traffic: one arc per source country, landing at the home point (Switzerland by default). An arc takes the colour of the sensor family that sends most traffic from that country, and gets thicker with more events. Presets are "World" (the default) and "Europe"; the last choice is remembered. Drag, scroll, pinch or use the arrow keys, `+`, `-`, `E` and `0` to pan and zoom.
- **Stats strip.** Events per minute, in total and per sensor family, in the top-left corner of the map (or under it on phones). The family colour is also the arc colour, so the strip is the legend. Click a family to filter the page. Click it again to clear the filter.
- **Ticker.** The newest events, as one row of chips under the map. Hover or focus the ticker to hold it still. New events then wait behind an "N new events" pill. Click the pill to catch up.
- **Rankings.** Three cards show the top addresses, the top countries and the top networks over the same 15 minutes. Each card opens with a sentence, such as "France leads with 21% of events, from 10 addresses." Each row opens the filtered Attacks view.

Hovering a ranking row, a ticker chip or a map dot highlights that country everywhere. Its arc becomes fully opaque, and the other arcs fade. **Pause** freezes the map, the rankings and the ticker at the newest event.

The home point comes from `GET /api/v1/settings/site`. Its position is set with `SITE_HOME_LAT` and `SITE_HOME_LON` (see [Configuration](configuration.md#site-live-map-home)).

With "reduce motion" set in the system, the arcs do not animate, the ticker does not glide and the numbers do not tween. The picture stays the same.

## The live feed

The Live page and the status dot in the header share one connection per browser tab.

- **WebSocket.** The app connects to `/api/v1/live`. It receives the 50 newest events first, then each new event, and statistics every 5 seconds.
- **Reconnects.** When the socket closes, the app retries with exponential backoff and jitter (1 s, 2 s, 4 s, up to 30 s). The dot shows "Reconnecting".
- **Polling fallback.** After 3 failed attempts in a row, or when the server refuses the socket (full, or origin not allowed), the app reads `/api/v1/events/recent` every 10 seconds while it keeps trying to reconnect. The dot then reads "Live" with a "Polling" note.
- **Refusals.** If the server is full (close code 1013), the app waits a minute before it tries again. If the origin is rejected (1008), it waits five minutes, because only a configuration change fixes it. See [Behind a TLS-terminating tunnel](deployment.md#behind-a-tls-terminating-tunnel).
- **Heartbeat.** The app sends a `ping` every 25 seconds.
- **Hidden tabs.** After five minutes in the background, the app disconnects. It reconnects when the tab is visible again.
- **Hold to read.** When you scroll away from the top of the feed, hover it, or press pause, new events wait in a counter ("N new events, jump to latest") instead of moving the list. The buffer keeps the newest 500 events.
- **Slow clients.** If the server had to skip messages for this tab, the app is told how many (`dropped`), and it can say so.

## Today, search and the glossary

**Today** is the page you land on. Its sentences are written by the API (`GET /api/v1/today`), so they match the numbers on the other pages. A card with nothing to report keeps its place and says so.

**Search** is the box at the top of every page on a computer, and the magnifier in the top bar on a phone. `Ctrl+K` (`Cmd+K` on a Mac) opens the same search from anywhere. Type an address, the start of an address ending in a dot such as `203.0.113.`, a CVE id, a file hash, a domain or a URL, or the start of a campaign name. Results are grouped, at most five per group, and Enter opens the first one: an attacker profile, a campaign, the CVE watch, or the Infrastructure page. Indicators are shown defanged and never as links.

**Glossary.** Security words in the interface (ASN, KEV, campaign, indicator, and more) have a dotted underline. Hover, tap or press Enter on one to read what it means in a sentence or two.

**Research scanners.** Known, harmless crawlers such as Censys and Shodan are labelled when they connect and hidden by default, so they do not drown the real attacks. The **Hide research scanners** switch in the header (the navigation drawer on a phone) shows them again, with the number of sessions the last 24 hours hid. The list lives in `ingest/rules/scanners.yaml`. A scanner is recognised by the network that owns its address, never by what it says about itself (a user-agent can be forged). Even then a session stays labelled only while it just looks around: it may connect, probe and send GET, HEAD or OPTIONS requests. A login attempt, a command, a download, a POST, an exploit flag or an attack tag makes it a normal session for good, and its earlier events too. Charts that cover more than a few days come from pre-computed totals that do not separate scanners, so they include scanner traffic.

**Motion.** Cards and pages fade in softly. With `prefers-reduced-motion`, or `?motion=off`, nothing moves.

## Screenshot mode

Real attack data contains attacker addresses. To take a screenshot, turn on **Mask IPs** in the sidebar footer, or open any page with `?mask=1`. Use `?mask=0` to turn it off. The choice is remembered per browser.

- An IPv4 address is masked to its first two parts: `203.0.113.42` becomes `203.0.x.x`.
- The masking also applies to addresses inside free text: URLs, commands, live summaries, the IP filter chip and page headlines.
- Copy buttons are hidden while masking is on.

README and documentation screenshots must use demo data only, even with the mask on. See [Demo data](demo-data.md).

## Keyboard and accessibility

- Every control is a real link or button. Tab moves through the page in reading order, and the focus ring is always visible.
- Whole rows in the Attacks list and the Live feed are links: Tab to a row and press Enter to open the session. The tag badges and address chips inside a row stay separately focusable.
- Colour is never the only signal. Sensors have an icon and a name, severity has an icon and a label.
- Text colours are checked for WCAG AA contrast in both themes by an automated test.
- There are no custom keyboard shortcuts yet.

## Terminal replay safety

```{admonition} Status
:class: warning

The terminal replay is **planned for M5**. It is not in the app yet. The contract below is a requirement for it.
```

SSH sessions are recorded with the bytes the attacker typed and the bytes the server sent back. An attacker controls those bytes, and a terminal emulator interprets escape sequences. The replay must therefore be built under the rules in [Security](SECURITY.md#terminal-replay-safety-contract).

## Run it locally

```bash
just web-dev
```

The Vite dev server starts on `http://127.0.0.1:5173` with mock data, so you do not need the stack. `just screenshots` takes desktop (1440 px) and mobile (390 px) screenshots in dark and light themes, on mock data. See [Development](development.md).
