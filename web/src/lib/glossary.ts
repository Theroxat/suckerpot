/**
 * Plain-English definitions of the security terms the UI uses, for the `Term` component.
 * Written for IT staff who are not security specialists: one or two short sentences, no jargon
 * inside the definition itself, nothing that needs a second lookup.
 */
export interface GlossaryEntry {
  /** The word as shown when a screen does not give its own text. */
  term: string
  /** Shown in the tooltip: at most about 200 characters. */
  short: string
}

export const GLOSSARY = {
  asn: {
    term: "ASN",
    short:
      "Autonomous System Number: the ID of the network (an ISP, a hosting company, a cloud) an address belongs to. Blocking an ASN blocks every address that network owns.",
  },
  cve: {
    term: "CVE",
    short:
      "A public ID for one known software flaw, such as CVE-2026-109618. Look it up to see which versions are affected and whether a patch exists.",
  },
  kev: {
    term: "KEV",
    short:
      "Known Exploited Vulnerabilities: a list by the US cyber agency CISA of flaws that attackers are using right now. Patch these first.",
  },
  rce: {
    term: "RCE",
    short:
      "Remote code execution: a flaw that lets a stranger run commands on your server over the network. The most serious kind.",
  },
  exploit: {
    term: "Exploit",
    short:
      "A request or program built to abuse a specific flaw, so the attacker gets access they should not have.",
  },
  payload: {
    term: "Payload",
    short: "The harmful program or script an attacker tries to drop on a machine after getting in.",
  },
  "brute-force": {
    term: "Brute force",
    short:
      "Trying many passwords, one after another, until one works. Strong, unique passwords and lockouts stop it.",
  },
  "credential-stuffing": {
    term: "Credential stuffing",
    short:
      "Trying username and password pairs leaked from other sites, hoping people reused them. A second factor stops it.",
  },
  botnet: {
    term: "Botnet",
    short:
      "A crowd of hacked devices, often routers and cameras, controlled by one attacker and used to scan, attack or mine coins.",
  },
  c2: {
    term: "C2 server",
    short:
      "Command and control: the server that remote-controls infected machines. They call home to it for orders or more malware. Blocking it cuts the attacker off.",
  },
  campaign: {
    term: "Campaign",
    short:
      "Several attacks that share the same tools, scripts or servers, so they are probably one operation rather than random noise.",
  },
  technique: {
    term: "ATT&CK technique",
    short:
      'A named attacker behaviour from the MITRE ATT&CK catalogue, such as "brute force" or "download a tool". Security teams use the same names, so you can match them to your detections.',
  },
  indicator: {
    term: "Indicator",
    short:
      "A trace of an attack that you can look for or block: an address, a domain, a web link or a file fingerprint (hash).",
  },
  hash: {
    term: "Hash",
    short:
      "A short fingerprint of a file. Two files with the same hash are the same file, so you can search for it without sharing the file.",
  },
  defanged: {
    term: "Defanged",
    short:
      "Written so it cannot be clicked or looked up by accident, for example hxxp://bad[.]example. Safe to paste into a chat or a ticket.",
  },
  "research-scanner": {
    term: "Research scanner",
    short:
      "A harmless crawler that maps the internet and publishes what it finds, such as Censys or Shodan. It is hidden by default; turn the switch off to see it.",
  },
  honeypot: {
    term: "Honeypot",
    short:
      "A decoy server with no real data. Nobody has a reason to visit it, so every visit is a probe or an attack, and everything is recorded.",
  },
  "known-scanner": {
    term: "Known scanner",
    short:
      "An address that GreyNoise has seen scanning the whole internet. It is noise aimed at everyone, not at you in particular.",
  },
  "abuse-score": {
    term: "Abuse score",
    short:
      "AbuseIPDB's 0 to 100 rating of how often an address was reported for abuse. Above 75 is usually worth blocking.",
  },
  blocklist: {
    term: "Blocklist",
    short:
      "A list of addresses or domains that your firewall or proxy should refuse. SuckerPot builds one from what it saw.",
  },
  malware: {
    term: "Malware",
    short:
      "A harmful program, such as a virus or a crypto-miner, that an attacker tries to put on a machine that is not theirs.",
  },
  scanner: {
    term: "Scanner",
    short:
      "A robot that knocks on every address and every door of the internet to see what answers. Most visits are just this.",
  },
  ssh: {
    term: "SSH",
    short:
      "Secure Shell: the usual way to log in to a server and type commands from far away. Attackers love to guess its passwords.",
  },
  telnet: {
    term: "Telnet",
    short:
      "An old, unprotected way to log in to a device remotely. Cheap cameras and routers still use it, which is why robots target it.",
  },
  rdp: {
    term: "RDP",
    short:
      "Remote Desktop Protocol: the way to control a Windows computer's screen from far away. A common way in for ransomware gangs.",
  },
  "ip-address": {
    term: "IP address",
    short:
      "The number that identifies a machine on the internet, a bit like a phone number. Here it is the machine that knocked on your doors.",
  },
} as const satisfies Record<string, GlossaryEntry>

export type TermId = keyof typeof GLOSSARY

export const TERM_IDS = Object.keys(GLOSSARY) as TermId[]

export function isTermId(id: string): id is TermId {
  return Object.hasOwn(GLOSSARY, id)
}

export function lookupTerm(id: string): GlossaryEntry | undefined {
  return isTermId(id) ? GLOSSARY[id] : undefined
}

/** The words in running text that open a definition (matched whole, case-insensitively). */
const SURFACE: [RegExp, TermId][] = [
  [/\bASNs?\b/i, "asn"],
  [/\bCVEs?\b/i, "cve"],
  [/\bKEV\b/, "kev"],
  [/\bRCE\b/, "rce"],
  [/\bexploits?\b/i, "exploit"],
  [/\bpayloads?\b/i, "payload"],
  [/\bbrute[- ]force\b/i, "brute-force"],
  [/\bcredential stuffing\b/i, "credential-stuffing"],
  [/\bbotnets?\b/i, "botnet"],
  [/\bC2\b/, "c2"],
  [/\bcampaigns?\b/i, "campaign"],
  [/\bindicators?\b/i, "indicator"],
  [/\bhoneypot\b/i, "honeypot"],
  [/\bblocklists?\b/i, "blocklist"],
]

export type TextPart = string | { id: TermId; text: string }

/**
 * Cut `text` into plain strings and glossary hits. Each term is explained once (its first
 * mention); `only` limits which terms may be picked. Overlaps resolve to the earliest match.
 */
export function splitTerms(text: string, only?: readonly TermId[]): TextPart[] {
  const hits: { start: number; end: number; id: TermId }[] = []
  for (const [pattern, id] of SURFACE) {
    if (only && !only.includes(id)) continue
    const m = pattern.exec(text)
    if (m) hits.push({ start: m.index, end: m.index + m[0].length, id })
  }
  hits.sort((a, b) => a.start - b.start)
  const parts: TextPart[] = []
  let at = 0
  for (const h of hits) {
    if (h.start < at) continue
    if (h.start > at) parts.push(text.slice(at, h.start))
    parts.push({ id: h.id, text: text.slice(h.start, h.end) })
    at = h.end
  }
  if (at < text.length) parts.push(text.slice(at))
  return parts.length ? parts : [text]
}
