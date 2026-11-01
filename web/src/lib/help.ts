/**
 * The text of every page's "?" popover, in one place so it can be reviewed together.
 * Each text is two or three plain sentences: what the page shows, where its data comes from,
 * and one useful action. Never describe a feature the page does not have.
 */

export interface HelpText {
  /** Shown as the popover heading. */
  title: string
  body: string
}

export const HELP = {
  today: {
    title: "Today",
    body: "Today tells the last 24 hours in plain words, from the events the sensors recorded. The flow diagram shows where visitors came from, which door they knocked on and how far they got. Click a block or a story to open the matching list of attacks.",
  },
  live: {
    title: "Live",
    body: "A map of the last 15 minutes of attacks, fed by the sensors over a live connection. Each arc is one source country landing on your home point, coloured by the kind of sensor it hit most. Click a sensor family in the stats strip to filter the page, or press Pause to freeze the picture.",
  },
  attacks: {
    title: "Attacks",
    body: "Every connection to a sensor is a session, told as one line. The sensors record the events and ingest adds the country, network and reputation of each address. Use the filters (sensor, period, tag, country, network) and share the address of the page: the filters live in the URL.",
  },
  session: {
    title: "Session",
    body: "One session as a timeline of what the visitor sent and what the sensor answered. Shell sessions can be replayed in a terminal at real speed, and the side panel shows the source address and its other visits. Click the address, a tag or a country to open every session that matches.",
  },
  attackers: {
    title: "Attackers",
    body: "One profile per source address: when it was first and last seen, which sensors it targeted and how it is rated. Reputation scores appear when you have added the provider keys in Settings. Click an address to see everything it did.",
  },
  attacker: {
    title: "Attacker",
    body: "Everything one address did across all sensors: when it came, what it tried and what happened. The reputation and network details come from the enrichment done when its first event arrived. Click a session to read the story, or a network to see its other addresses.",
  },
  networks: {
    title: "Networks",
    body: "The hosting providers and networks (ASNs) that attacks come from, counted from the same sessions as the Attackers list. Many addresses in one network often means one operator or one hosting farm. Click a network to see its sessions.",
  },
  activity: {
    title: "Activity",
    body: "The last 24 hours in numbers: sessions, addresses, activity per sensor and the latest events, with up to three written insights. Everything is counted from the stored events, and fixed rules write the insights. Click an insight to open the evidence behind it.",
  },
  patterns: {
    title: "Patterns",
    body: "The most tried usernames, passwords, commands and URLs, tags over time, a day by hour heatmap and what is new this week. All of it is counted from the stored events over the period you pick. Click a value to open the sessions that used it.",
  },
  campaigns: {
    title: "Campaigns",
    body: "Sessions that share a script, a payload host, a file hash, a malware family, an exploit or a credential list are grouped into one campaign with a short story. Ingest finds them on its own when the campaigns worker is on. Open a campaign to see its timeline and its sessions.",
  },
  campaign: {
    title: "Campaign",
    body: "One campaign: the story, the shared evidence that links its sessions, and when it started and stopped. It is built by ingest from the sessions that share the same script, host, hash or exploit. Click an item of evidence to open the sessions that carry it.",
  },
  techniques: {
    title: "Techniques",
    body: "The MITRE ATT&CK techniques seen in the attacks, as a heatmap per day. Ingest maps tags and commands to techniques when the ATT&CK worker is on. Click a technique to see the sessions behind it.",
  },
  scripts: {
    title: "Scripts",
    body: "The library of command scripts that attackers typed, with copies merged into one entry. Each script has an explanation, written by fixed rules or, only if you switched the optional explainer on, by a language model. Open a script to read it and see which sessions used it.",
  },
  script: {
    title: "Script",
    body: "One script that attackers typed on a fake shell, with what it does and every session that used it. The sensor only recorded the text: nothing was ever run. Click a session to read the whole attack.",
  },
  malware: {
    title: "Malware",
    body: "The download URLs that attackers tried to use, shown defanged so they cannot be opened by mistake. Sensors only record a URL: when payload fetching is on, the collector fetches it through the VPN into quarantine and the Samples tab shows the files. Open a sample to read its analysis.",
  },
  sample: {
    title: "Sample",
    body: "One file the collector fetched, kept in quarantine and never run. The analyzer reads it with no network access: type, hashes, rule matches, the unwrapped script and strings. Administrators can download it as a password-protected archive for analysis elsewhere.",
  },
  infrastructure: {
    title: "Infrastructure",
    body: "The addresses, hosts and files that show up across sessions, as defanged text, never as links. A payload host or command server shared by several attackers is a link between them. Export the indicators as CSV or STIX 2.1 for your own tools.",
  },
  blocklists: {
    title: "Blocklists",
    body: "Addresses, domains, URLs and hashes seen attacking you, each scored from 0 to 100 with a reason for every point. Ingest rescores them every 15 minutes when the blocklist worker is on. Download a list for your firewall, or add an override to always allow or always block a value.",
  },
  detections: {
    title: "Detections",
    body: "Sigma and Suricata rules written from what the sensors recorded, plus a checklist for your own company. They come from decoy traffic and can match harmless activity, so review them before deploying. Switch the format, then copy or download a rule.",
  },
  exposure: {
    title: "Your exposure",
    body: "Your own services next to what the sensors recorded against the same kind of service. You type in the inventory; the attack counts come from the stored sessions. Add a service to see how much it is attacked and which known exploited vulnerabilities apply.",
  },
  cves: {
    title: "CVE watch",
    body: "New and known-exploited vulnerabilities, ranked by how much they matter to the services the sensors emulate. They are fetched from public feeds through the VPN, and matched with what was seen in your traffic. Open a CVE for the details, or watch it to hear when it shows up.",
  },
  alerts: {
    title: "Alerts and reports",
    body: "Rules that tell you when something happens, such as a new campaign, a malware drop or a watched CVE, and the weekly report. Everything is off until you switch it on, and messages leave through the VPN. Add a channel in Settings, then turn a rule on.",
  },
  report: {
    title: "Weekly report",
    body: "One week summarised: the numbers, what changed and the notable attacks. It is built every Monday from the stored events. Use the print view to save it as a PDF.",
  },
  abuse: {
    title: "Abuse reports",
    body: "Drafts of reports for the networks that host attackers, with the abuse contact looked up over RDAP through the VPN. SuckerPot never sends a report: you review a draft, copy it and send it from your own mailbox. Open a draft to read the identity check first.",
  },
  "abuse-report": {
    title: "Abuse report",
    body: "One draft report for one abuse desk. The identity check says what was masked, or why the report is blocked, against your own addresses and the terms you listed in Settings → Reporting. Review it, copy the message, send it yourself, then mark it as sent.",
  },
  "settings-general": {
    title: "General",
    body: "Sensor health, storage, retention and the state of outbound traffic, read from the running stack. The setup checklist shows what is left to configure. Most options live in the .env file on the host, and changing them needs a restart.",
  },
  "settings-keys": {
    title: "Keys",
    body: "The optional API keys for the reputation providers that enrich each address. They are write-only: you can set, replace, test or remove a key, and each change asks for your password. Lookups go through the VPN and stay within the free-tier quotas.",
  },
  "settings-users": {
    title: "Users",
    body: "The people who can sign in: administrators change things, viewers only read. A new person gets a temporary password, shown once, and chooses their own at first sign-in. Each change asks for your own password again.",
  },
  "settings-audit": {
    title: "Audit",
    body: "Who did what in the dashboard, newest first: sign-ins, user changes and key changes. The log is append-only and written by the API. Click a name to filter by that person.",
  },
  "settings-alerts": {
    title: "Alert channels",
    body: "Where alerts are delivered: Discord, Microsoft Teams or email. The target is checked and stored encrypted, and messages leave through the VPN. Send a test message, then turn rules on from the Alerts page.",
  },
  "settings-feeds": {
    title: "Feeds",
    body: "Subscription links that let a firewall fetch the blocklists without signing in. A token is shown once, can be limited and can be revoked at any time. Feeds are off unless the stack is configured for them.",
  },
  "settings-reporting": {
    title: "Reporting",
    body: "The wording used in abuse reports: your reply contact, signature, introduction and closing, plus the list of terms that must never appear in a report. Fill every field so drafts are complete. The identity check blocks a report that contains one of those terms.",
  },
  "settings-vpn": {
    title: "VPN",
    body: "Where outbound traffic leaves. Only the vpn service has a route to the internet, and the gate pauses every lookup when the tunnel or its exit looks wrong. You can check now, reconnect, upload a new WireGuard file and trust a new exit.",
  },
  styleguide: {
    title: "Styleguide",
    body: "Every colour token and base component in every state. It is the page the visual review screenshots. Switch the theme to check both.",
  },
} as const satisfies Record<string, HelpText>

export type HelpId = keyof typeof HELP

export const HELP_IDS = Object.keys(HELP) as HelpId[]

/** The help id of a Settings tab; unknown tabs fall back to General. */
export function settingsHelpId(tab: string): HelpId {
  const id = `settings-${tab}`
  return id in HELP ? (id as HelpId) : "settings-general"
}
