# Dashboard

The dashboard is a single-page web app in `web/`. The API serves the built files, so there is one port to publish and one thing to put behind the tunnel. The design rules are in `web/DESIGN.md`. Colour tokens, the type scale and every component are shown on the `/styleguide` page of a running dashboard.

```{admonition} Build status
:class: note

**Built:** the app shell, the design system, the login page, **Live** (feed), **Overview** (with insights), **Attacks**, **Session detail**, **Attackers** (list and profile), **Trends** and **Malware**.

**In progress:** the 3D globe on the Live page (it uses `GET /api/v1/settings/site` for the landing point) and the terminal replay (M5).

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
| Live | `/live` | Feed built, globe in progress | A live feed of events as sensors record them, and events per minute for each sensor. The globe shows attack arcs landing at the home point. |
| Overview | `/overview` | Built | KPIs for the last 24 hours, activity per sensor, the sensor mix, the latest events and up to three insights (see below). |
| Attacks | `/attacks` | Built | Sessions, newest first, one line each, as a short story. Filters: sensor, source address and period in the app today. The API also filters by tag, country and network. Pages of 50, virtualised. |
| Session detail | `/attacks/<session id>` | Built (replay in progress) | The attack timeline, with long runs of the same event folded, and a source panel. |
| Attackers | `/attackers`, `/attackers/<ip>` | Built | Profiles by address and by network: first and last seen, sensors targeted, reputation. |
| Trends | `/trends` | Built | Top usernames, passwords, commands and URLs, tags over time, a day by hour heatmap, and "new this week" (values never seen in the 90 days before). |
| Malware | `/malware` | Built | Download URLs, defanged, with how often, from how many addresses and with which tool. File hashes and VirusTotal links appear only if payload fetching exists, which it does not yet. |
| Settings | `/settings` | Built | Sensor status, enrichment quotas, retention, the disk guard and the database size. The enrichment API keys (AbuseIPDB, GreyNoise, MaxMind) can be set, replaced, removed and tested here: write-only, with a password prompt for every change (see [Enrichment keys in Settings](configuration.md#enrichment-keys-in-settings)). It uses `GET /api/v1/settings/system`, `/settings/enrichment` and `/settings/providers/{provider}`. |
| Styleguide | `/styleguide` | Built | Every token and component, in every state. |

## Sign in

When the API answers `401`, the app shows the sign-in page. After a successful login the session lasts `SESSION_TTL_HOURS` (12 by default). The cookies are set by the server; the app never stores the password or a token in the browser's storage. The app reads the CSRF cookie and sends it on every write. Too many attempts show "Wait a minute, then try again". If login keeps failing behind a tunnel (the API answers `403` to a cross-origin login), add the public origin to `API_ALLOWED_ORIGINS` (see [Deployment](deployment.md#behind-a-tls-terminating-tunnel)).

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

## The live feed

The Live page and the status dot in the sidebar share one connection per browser tab.

- **WebSocket.** The app connects to `/api/v1/live`. It receives the 50 newest events first, then each new event, and statistics every 5 seconds.
- **Reconnects.** When the socket closes, the app retries with exponential backoff and jitter (1 s, 2 s, 4 s, up to 30 s). The dot shows "Reconnecting".
- **Polling fallback.** After 3 failed attempts in a row, or when the server refuses the socket (full, or origin not allowed), the app reads `/api/v1/events/recent` every 10 seconds while it keeps trying to reconnect. The dot then reads "Live" with a "Polling" note.
- **Refusals.** If the server is full (close code 1013), the app waits a minute before it tries again. If the origin is rejected (1008), it waits five minutes, because only a configuration change fixes it. See [Behind a TLS-terminating tunnel](deployment.md#behind-a-tls-terminating-tunnel).
- **Heartbeat.** The app sends a `ping` every 25 seconds.
- **Hidden tabs.** After five minutes in the background, the app disconnects. It reconnects when the tab is visible again.
- **Hold to read.** When you scroll away from the top of the feed, hover it, or press pause, new events wait in a counter ("N new events, jump to latest") instead of moving the list. The buffer keeps the newest 500 events.
- **Slow clients.** If the server had to skip messages for this tab, the app is told how many (`dropped`), and it can say so.

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
