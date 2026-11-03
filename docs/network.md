# The Selfhostr network

The Selfhostr network is an opt-in pool. Many Selfhostr systems share what their sensors saw, in aggregate and without identities. The network confirms a target only when several independent sensors agree. It then sends one strong abuse report instead of many weak ones, and it follows the takedown.

This page is for members and for people who want to know what joining means. The hub operator reads `hub/README.md`. The exact wire format is in [Network protocol](network-protocol.md). The design and its review are in [M29](design/m29.md).

```{warning}
Joining is a choice. Selfhostr never joins the network for you, and nothing is sent until you have turned it on and joined in the dashboard.
```

## What joining means

Joining turns your sensors into one voter in a shared network. Your system then:

- sends one daily batch of attacker addresses and a few related facts (see [What is shared](#what-is-shared-and-what-never-is));
- receives the list of targets the network has confirmed, and shows it to you;
- can see the network's totals and which members take part.

You do not get a share of anything, and you do not get better detection. The benefit is for the internet: an address that many sensors agree on is more likely to be removed, and the people who run it are more likely to be told.

Your system stays on your own machine. Nothing is installed on the hub side for you, and no account or e-mail address is created.

## Strictly opt-in

Two steps must both be true before a single byte goes to the hub:

| Step | Who | Where | Default |
| --- | --- | --- | --- |
| 1. Allow the network on this system | You | `just set NETWORK_ENABLED=true` on the host (it writes `.env` and restarts the services that read it) | `false` |
| 2. Join the network | An administrator | Settings, Network: join, with the password typed again and five consents ticked | Not joined |

If step 1 is off, the Network pages explain the situation and nothing else happens. The node worker does not contact the hub at all. If step 2 is not done, the worker stays idle.

Other rules:

- Leaving takes one click and the password. See [How to leave](#how-to-leave).
- Viewers can read the Network pages but cannot join or leave. Only an administrator can.
- Joining again after you leave is a new decision, made in the same way.

## What is shared and what never is

When you join, you tick five boxes. Each box is one kind of data. The API refuses a join unless all five are ticked.

| Box | What is sent | Form |
| --- | --- | --- |
| Attacker addresses | The addresses that attacked your sensors | Clear IP address, with the kind of service (for example `ssh`, `web`), a coarse activity (`connect`, `scan`, `login`, `login_success`, `command`, `download`, `exploit`, `http`), behaviour tags and rounded counts |
| Download links | Links that attackers tried to fetch malware from | Blinded: a SHA-256 hash of the normalised link. The clear link is revealed only after the network confirms the hash and a member holds the clear link |
| Malware file fingerprints | SHA-256 of a captured file, its family and its file type | Hash only. The file is never sent |
| Command servers | Address or domain and port of a command-and-control server | Only high-confidence links, and only when a dropper that several sensors fetched backs them |
| Takedown checks | Whether a reported target still answers | `up` or `down`. Nothing is sent yet, see [Takedown checks](#takedown-checks) |

### What is never shared

These things never leave your system, whatever you tick:

- usernames and passwords that attackers tried;
- commands typed in a shell, and web requests;
- source and destination ports, and exact times (only the UTC day is sent);
- anything from research scanners or from harmless visitors;
- your own address, domain, host name or dashboard address, in any spelling;
- private, reserved and documentation addresses;
- anything on your never-block list.

Your private key never leaves your system. It is stored encrypted and used only to sign requests. Your public key goes with every signed request, because the hub needs it to check the signature.

### What the hub can see about you

The hub sees what a batch contains, and the requests that carry it. It does not see:

- your name, mailbox, payment or account (there is none);
- your IP address. The hub keeps no client address. Requests go out through the VPN, so the hub sees a VPN exit;
- your domain or host name.

If you choose a pseudonym, the hub sees it. If you choose a country and show it, the hub sees that too.

### Identity controls on your side

Before a batch leaves, every item passes the same identity check that protects your abuse reports. The check drops an item that contains your own address, a domain you use, or any term you have listed as yours. A batch that fails the check as a whole is not sent.

Nothing is sent until you confirm your own address in Settings, Reporting. Without a confirmed address, the node shows that it is waiting for your address and sends nothing. This is on purpose. It stops your own address from leaving in a batch by mistake.

```{note}
Test traffic counts. If you test your sensors from an outside address that is not in your address terms, that address is submitted like any attacker's. Add your test address to your terms, or expect it to appear in a batch.
```

## What you get back

| Item | What it is |
| --- | --- |
| Totals | Members, members active this week, countries with at least three members, confirmed, reported and taken-down targets over 30 days, median days to takedown |
| Weekly figures | Confirmed, reported and taken-down targets per week |
| Recently taken down | Targets, with the number of sensors (as a range) and a "You helped" mark when your system contributed |
| Members | Pseudonym or node number, country (only if the member showed it), member since (a month), active days in the last full week, and a tier |

Nothing in the public figures can point to a single system. There is no ranking, and the member list is shuffled by the hub on every day.

## The community lists

The network also publishes free blocklists. They are built from the same consensus as the hub's reports. Any firewall can load them, and they cost nothing to use.

| List | Blocks | Built from |
| --- | --- | --- |
| `outbound` | Traffic leaving your network to malware hosts and command servers | Payload hosts fetched by at least 2 nodes, with a known malware family or an executable or script file type. Command servers with high-confidence analysis and at least 2 samples from 2 nodes. |
| `inbound` | Traffic coming in from attack sources | Addresses with login success, commands, downloads, exploits or repeated login attempts, seen over TCP by at least 5 nodes |
| `outbound-domains` | DNS lookups of the same hosts, by name | The names behind the `outbound` evidence |

The `-high` variants hold the stricter subset. The full rules, the formats and the steps for each firewall are in [Community blocklist feeds](feeds.md).

The lists are published by the hub, from its own server. A member's home connection is never the source of a list. Nothing in a list names a member, a country, a sensor or a day of sighting. An entry needs at least five independent sensors before it can appear at all, and no single sensor's sighting changes a list.

### Why join, and what it changes

The lists are free and public. Anyone can use them, member or not. Joining does not unlock a better list.

What joining does change:

- Your sensor's sightings become one of the votes that confirm an entry. More sensors, faster and more accurate lists.
- The Network tab tells you which entries your sensor also saw, and which ones it helped confirm. You can see the effect of your own sensor.

Joining does not give you a private list or an early copy. Members get the same files as everyone else.

## How consensus protects against poisoning

Poisoning means that someone sends false sightings to get an innocent address or site listed. The network makes this expensive. A single node can never publish anything.

A value becomes a **confirmed target** only when all of these hold:

1. **Enough nodes.** At least 5 eligible nodes saw it.
2. **Enough weight.** The reputation of those nodes adds up to at least 3.0. A node counts at most 1.0. A new node starts at 0.6, so five new nodes make exactly 3.0.
3. **Enough days.** The sightings come from at least two different days, or from 10 nodes.
4. **No single cohort.** No single enrolment week supplies more than half of the nodes. A farm that signs up in one go cannot confirm alone.
5. **Corroboration for addresses.** An address seen by 5 to 9 nodes also needs a known-bad signal from the hub's optional lookup sources (AbuseIPDB or GreyNoise, if the operator has keys), or else 10 nodes. A hub without lookup keys always needs 10. Links, domains and command domains always need 10 nodes.
6. **Dropper for command servers.** A command server counts only with a file that at least two eligible nodes fetched, and with at least five of its own nodes that fetched the same file.
7. **Never-list.** Public resolvers, large CDN and SaaS domains, update servers, package registries, reserved ranges and the operator's own entries never confirm.

An **eligible node** must:

- be at least 14 days old;
- have sent data on at least 7 of the last 14 days (an empty batch does not count);
- have a reputation of at least 0.3;
- not be suspended.

### Reputation

Each node has a hidden reputation number. It rises a little when its sightings confirm a target, and more when a confirmed target is taken down. It falls when a sighting is disputed, and when a node sends a large volume that nobody else ever sees. Below 0.2 a node is soft-suspended. Its batches are accepted and then ignored, and it is not told. The number itself is never sent. Members only see `new`, `good` or `low`.

### Published values only change with consensus

The first and last day, the services, the activity, the tags and the families of a listed target change only when at least five eligible nodes support the change. One sighting from one node can never change what members see about a listed target. This stops an attacker from using a listed address to test whether one particular address is a sensor.

### Reports

Scans and connections alone are never reportable. The hub reports only:

- addresses with a severe activity (a login that worked, a command, a download or an exploit) seen by enough nodes, or with 100 or more login attempts from enough nodes;
- links and files that at least two nodes fetched;
- command servers that are confirmed.

Reports are grouped: at most one report per abuse desk and kind in a week. In the first release an operator reviews each report before it goes out. Command-server reports are never sent automatically. See `hub/README.md`.

### What consensus does not stop

A patient operator with at least five aged, well-behaved nodes can get a false target through. The reputation rules slow this down, and human review of reports is the last barrier. Consensus is a strong filter, not a proof.

## How to join

Before you start, make sure these hold:

- `NETWORK_HUB_URL` and `NETWORK_HUB_KEY` are set in `.env`. The project provides both with a hub. Until a hub exists, both stay empty and the network cannot be joined.
- `SETTINGS_ENCRYPTION_KEY` is set. The node key is stored encrypted, and without this key the network refuses to store it.
- Your own address is confirmed in Settings, Reporting.

Then:

1. On the host, run `just set NETWORK_ENABLED=true`. It writes `.env` and restarts `ingest` and `api` so they read it. If the project gave you a hub address and key, set them the same way: `just set NETWORK_HUB_URL=https://hub.example.org NETWORK_HUB_KEY=<key>`.
2. Open **Settings, Network** and read the page. It lists what is shared and what is never shared.
3. Press **Join the network**. The dialog asks for:
   - the five consents, one box each;
   - an optional pseudonym. Do not use a name that you use anywhere else;
   - an optional country. It is never detected for you. It is shown only if you tick "Show my country" and at least three members share it;
   - your dashboard password again.
4. The sensor creates its key and solves a proof-of-work puzzle. This can take a few minutes on a small machine. It runs at low priority, so ingest keeps working. The hub can raise the puzzle's price when many systems sign up at once. While the hub is closed or the puzzle is too hard, the page says that enrolment is waiting, and the sensor retries by itself.
5. Your sensor is now a member. Its standing shows `new`. It sends its first batch after the next day ends, plus a random wait of 2 to 20 hours. Your sensor counts toward confirmations after 14 days of regular batches. The standing then changes to `good`.

### Pseudonyms

| Rule | Detail |
| --- | --- |
| Length | 3 to 24 characters |
| Characters | Letters, digits, space, `_`, `.` and `-`. Starts and ends with a letter or digit |
| Forbidden | `://`, `@`, four digits in a row, reserved words (for example `admin`, `hub`, `network`, `node`, `official`) and the names of this project |
| Owner check | The identity check refuses a name that contains your own names or domains |
| Changes | At most one change per 7 days, at the hub |

Empty means the network shows you as `Node` followed by your fingerprint, for example `Node 3f9a1c07`.

## How to leave

Open **Settings, Network** and press **Leave the network**. The dialog says what will be deleted, and asks for your password again. Then:

1. The worker asks the hub to delete your node. The hub deletes the node record and everything linked to it: its observations, its links to targets, its takedown votes, its weekly statistics and its request nonces.
2. Your system deletes its local key, its membership record, the list of targets it kept and its history of batches, including the exact JSON you could read.
3. The Network pages show you as not a member.

If the hub cannot be reached, the worker retries each cycle for up to seven days. After that it deletes everything locally and records `leave_unconfirmed`. The hub removes a node that stays silent for 30 days, so nothing stays active.

Two things are not deleted, and you should know why:

- **Published figures.** Totals that include your help stay. They are sums over many systems and carry no link to your node.
- **Hub backups.** The hub keeps daily database dumps for seven days. A deleted node can still be in an older dump until that dump is rotated out. See `hub/README.md`.

## The Network pages

The pages are in the **Defend** space. The **Network** entry has two tabs: **Overview** (`/network`) and **Members** (`/network/members`). Settings has a **Network** tab too.

### Overview

- **Not a member.** The page shows the join card and the explanation: what the network does, what is shared, what is never shared and the one residual risk. It shows no network figures, and it does not ask the hub for anything.
- **A member.** The first line says what the network did in the last 30 days, and what your sensor helped confirm. Under it:
  - a row of figures (active members this week, confirmed, reported, taken down, median time to takedown);
  - a weekly chart of confirmed, reported and taken-down targets;
  - a list of recently taken down targets, filtered in the URL by state, kind and "mine";
  - the **Your node** card: fingerprint, pseudonym (you can edit it), country, date you joined, eligibility, standing, last batch, and **See exactly what was sent**, which shows the stored JSON of your last batch with a copy button;
  - the **Leave the network** button.

### Members

A list of members with their pseudonym (or node number), country flag or a dash, date of joining, seven dots for the active days of last week, and a tier from 0 to 4. The tier is a count range, not a score. The list is sorted by pseudonym. There is no ranking by activity. The country filter is in the URL.

### Settings, Network

The same join and leave controls as on the Overview, with the node card. The "What is shared" and "What is never shared" lists are always here.

### Setup checklist

The setup checklist has a Network item. It is off when this system is not a member, green when it is a member and sent a batch in the last two days, and a warning with the reason when batches are waiting. The first-run setup has an optional Network step after Alerts. Its own "Skip for now" moves on and shares nothing. When `NETWORK_ENABLED` is false and no hub is configured, the step only says that the network is off.

## Takedown checks

The network can follow what happens after a report. Members check their own targets locally, and the hub counts the answers. A target is taken down after at least two nodes say `down` on three different days, with no `up` on the last of them.

This feature is not active yet. The local re-check it depends on is not part of this release. Until it exists:

- every local re-check answers `unknown`;
- the node sends a re-check only for `up` or `down`, so it sends nothing for this box;
- no target moves to `taken_down` because of a member.

The box stays in the join form so that the consent list does not change later. Ticking it now sends nothing.

## Threat model

This section answers one question for each party: what can they learn, and what can they do? The full analysis is in [M29, section 3](design/m29.md#3-threat-model).

### Who we worry about

| Party | What they have |
| --- | --- |
| **A1. Attacker** | Source addresses and download links they control. They know which addresses they hit and when. They can be a member. |
| **A2. Malicious member or a farm of fake members** | Many enrolled systems and forged sightings. |
| **A3. Curious hub operator** | The hub database and the hub's traffic. |
| **A4. Hub seized or compromised** | A full copy of the database at one moment. |
| **A5. Network observer** | Sees traffic between your system and the VPN, and between the VPN and the hub. |
| **A6. Abuse desk** | Receives a report, and may pass it on to the customer who runs the address. |
| **A7. Fake hub** | Tries to impersonate the hub to your system. |

### What a malicious member can learn

| Can learn | Cannot learn |
| --- | --- |
| Public figures, the target list and their states | Any other node's batches |
| Pseudonyms, fingerprints, countries that members chose to show, and a member's tier | Which address belongs to which member. A fingerprint is a hash of a public key, not an address |
| Whether an address they probed is listed, once it is confirmed | Which member saw an attacker, or when, at a finer level than a day |
| Whether their own sightings contributed to a listed target (they know their own data) | The sightings of a member they probed |

A member can send many forged sightings. They are weighted by reputation, age, enrolment week and corroboration, so a few members cannot make a target. A large patient farm can. The hub can then refuse, report only with human review, or dispute the target.

### What a malicious or curious hub can learn

| Can learn | Cannot learn, by design |
| --- | --- |
| For each node: its public key, pseudonym, country (if shown), enrolment day, last active day, reputation and standing | The IP address of any node. The hub keeps no client address in its code, its logs or its tables |
| For 14 days: the addresses, services and activity each node submitted, by day | A node's exact times, source or destination ports, usernames, passwords or commands |
| Which nodes sent a batch on a day | The clear value of a link that is not confirmed. Links are blinded |
| Report contents: day ranges, buckets, services, tags and families | Node identities in reports |

A hub operator who turns on logging against policy could link a VPN exit to a pseudonym. Each node then reaches the hub through a VPN exit, not through a home address. The design accepts that residual risk for version 1.

### What a hub compromise or seizure gives away

- The node public keys, pseudonyms and enrolment days of all members.
- Fourteen days of observations by node, at the day level.
- Blinded links. A link with a random token is hard to guess. A guessable link can be checked against a list of candidates, because the hash is fast and not salted. This is a known limit of protocol version 1 ([network-protocol.md](network-protocol.md#blinding)).
- The report texts and their recipients.

It does not give away the node keys' private halves, which never leave the nodes, or the hub's signing key, which is kept in a separate secret file. The hub's signing key is the one key an attacker must not get. If it leaks, see `hub/README.md`.

### What a network observer can learn

- That your system talks to the VPN, and how much.
- Requests to the hub are padded to a multiple of 4 KiB, so their size says little. The timing of one daily batch is visible.
- Nothing about the content. TLS and the request signatures protect it.

### What an attacker can learn about your sensors

An attacker that probes many addresses can learn that a set of addresses runs a Selfhostr sensor. Many probe addresses over weeks make this more likely. The attacker cannot learn which member runs them. This risk exists because your sensors answer connections, and it is the same with or without the network. The Overview says so before you join.

### What the community lists reveal

The lists are public, so they are visible to everyone, attackers included.

- **Member data:** none. Entries carry no node data. Every attribute that is published (services, tags, families, dates) needs at least five nodes behind it. One node's sighting of an address changes nothing public, not even its expiry.
- **Timing:** the lists are regenerated on a fixed hourly schedule, and new entries wait 6 hours after confirmation. The publication time says nothing about one member.
- **Downloads:** the feed site keeps no access log and sets no cookies. Nobody can see who fetches the lists.
- **Poisoning:** an attacker who controls many sensors could try to list a third party. Only the hub's own confirmed targets can enter a list, after stricter rules than reports. A text typed into a honeypot command never lists an address by itself. Public resolvers, CDNs, shared hosting and Tor exit relays are never listed.
- **Forgery:** each file is signed with a feed key that is separate from the hub's key. Your node checks the signature, the serial and the expiry before it stores anything.

### What is not protected

- A sensor that is reachable from the internet is already visible to every attacker who scans it.
- The hub operator can see the attacker addresses that nodes submit. These addresses belong to the attackers, not to members.
- The system's own logs (SSH, the host firewall, the Docker daemon on the host) are outside this design. Keep them private.

## Where to go next

| Read | When |
| --- | --- |
| [Network protocol](network-protocol.md) | You build a client or want to check a signature |
| `hub/README.md` | You run a hub |
| [Configuration](configuration.md#selfhostr-network-m29) | You want every `NETWORK_*` variable |
| [M29 design](design/m29.md) | You want the full analysis and the decisions |
