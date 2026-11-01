# Network protocol `spn/1`

This is the wire protocol between a Selfhostr node and a network hub. It is normative: the
reference implementation is the `suckerpot_netproto` package (`netproto/`), and its golden test
vectors (`netproto/tests/vectors.json`) are the contract for any other implementation. Design and
threat model: [M29](design/m29.md).

Every address and name below is a placeholder (documentation ranges and `example.org`).

## Transport

- HTTPS to the hub URL (for example `https://hub.example.org`), base path `/v1`. JSON, UTF-8,
  `Content-Type: application/json`. No compression.
- Request bodies are at most 1 MiB for `/v1/observations` and 64 KiB elsewhere. Every JSON object
  rejects unknown fields. JSON depth is at most 6.
- Client `User-Agent: spn-node/1`. No cookies. Redirects are not followed.
- The request body is padded: a `"pad"` field holds spaces so that the body length is a multiple
  of 4096 bytes. The body is compact ASCII JSON (`separators=(",", ":")`, non-ASCII escaped).

## Keys and signatures

- **Node identity.** An Ed25519 key pair made on the node. `node_key` is the base64url (no padding)
  encoding of the 32-byte public key. The fingerprint is the first 8 hex characters of
  `sha256(public key)`, shown as `Node 3f9a1c07`.
- **Request headers.**

  | Header | Content |
  | --- | --- |
  | `X-SPN-Key` | `node_key` |
  | `X-SPN-Timestamp` | Unix seconds, integer |
  | `X-SPN-Nonce` | base64url of 16 random bytes |
  | `X-SPN-Signature` | base64url Ed25519 signature of the canonical request string |

- **Canonical request string.** Lines joined with `\n`, no trailing newline:

  ```
  SPN1-REQ
  <METHOD uppercase>
  <path with query exactly as sent, for example /v1/targets?since=c_12&limit=1000>
  <X-SPN-Timestamp>
  <X-SPN-Nonce>
  <lowercase hex sha256 of the raw body bytes; of the empty string for GET and DELETE>
  ```

- **Hub checks**, in this order, before the body is parsed:
  1. size (`too_large`);
  2. headers present and well formed (`invalid_payload`);
  3. `|now - timestamp| <= 300` seconds (`stale_timestamp`);
  4. key known, except for enrolment (`unknown_node`);
  5. signature (`bad_signature`);
  6. nonce unseen for this key in the last 10 minutes (`replayed_nonce`);
  7. rate limit (`rate_limited`).
- **Response signature.** An answer to an authenticated request carries `X-SPN-Hub-Signature`:
  the Ed25519 signature by the hub key of

  ```
  SPN1-RESP
  <METHOD uppercase>
  <path with query exactly as sent>
  <X-SPN-Key of the request, or "-" for an unsigned request>
  <request X-SPN-Nonce>
  <lowercase hex sha256 of the request X-SPN-Signature string; for an unsigned request, the
   lowercase hex sha256 of the request body>
  <HTTP status code>
  <lowercase hex sha256 of the response body>
  ```

  The node checks it against the pinned hub key (base64url public key) and refuses the answer
  otherwise (`hub_signature`, a node-side code). The answer is bound to the whole request, not
  only its nonce: a man in the middle cannot send its own request to the hub, keep the signed
  answer and replay it to a victim's nonce.
- **Unsigned answers.** The hub does not sign an answer to a request whose authentication failed
  (`stale_timestamp`, `unknown_node`, `bad_signature`, malformed headers, an unknown route,
  `too_large`). A node treats such an error as "not authenticated", never as a statement by the
  hub, and only retries later.
- **Unsigned requests.** A client SHOULD send `X-SPN-Nonce` (16 random bytes, base64url) on the
  unsigned endpoints too. When the header is well formed, the hub signs its answer with the
  binding above (key `-`, body hash), so a node can check that `/v1/info` and the enrolment
  challenge come from the pinned hub. Without the header the answer carries no signature.
- **Client address.** The hub never stores or logs the client address. It keeps in memory only a
  keyed hash of it, under a random key replaced every day, to rate limit unsigned requests and
  repeated authentication failures.

## Errors

Status 4xx or 5xx with the body `{"error": "<code>"}`.

| Code | Status | Meaning |
| --- | --- | --- |
| `too_large` | 413 | Body over the size cap |
| `invalid_payload` | 400 | Schema or value validation failed |
| `unsupported_protocol` | 400 | Unknown `protocol` value |
| `stale_timestamp`, `replayed_nonce`, `bad_signature`, `unknown_node` | 401 | Signature checks |
| `pow_invalid`, `challenge_expired` | 400 | Enrolment proof |
| `pseudonym_invalid` | 400 | Pseudonym rules |
| `pseudonym_taken` | 409 | Pseudonym in use |
| `enrolment_closed` | 503 | Global enrolment cap reached |
| `rate_limited` | 429 | With `Retry-After` in seconds |
| `day_not_closed` | 400 | The day has not ended yet |
| `day_too_old` | 400 | The day is more than 3 days old |
| `server_error` | 500 | Anything else |

A soft-suspended node is never told: its requests succeed and its data is ignored.

## Endpoints

| Method | Path | Signed | Body and answer |
| --- | --- | --- | --- |
| GET | `/v1/info` | no | `{protocols, hub_key, pow: {algorithm, difficulty}, limits, thresholds: {min_nodes, min_age_days}, today}` |
| POST | `/v1/enrol/challenge` | no | `{protocol, node_key}` returns `{challenge, difficulty, expires_in}` |
| POST | `/v1/enrol` | by the new key | `{protocol, challenge, pow_nonce, pseudonym?, country?, show_country}` returns `{node_id, fingerprint, enrolled_day, eligible_from_day}` |
| GET | `/v1/node` | yes | returns `{node_id, fingerprint, pseudonym, country, show_country, enrolled_day, eligible_from_day, standing, active_days_14}` |
| PATCH | `/v1/node` | yes | `{protocol, pseudonym?, country?, show_country?}` returns the node |
| DELETE | `/v1/node` | yes | returns `{deleted: true}`; removes the node and everything linked to it |
| POST | `/v1/observations` | yes | a batch (below) returns `{accepted, rejected, duplicate}` |
| GET | `/v1/targets?since=<cursor>&limit=<1..1000>` | yes | returns `{cursor, targets, reveal, recheck}` |
| POST | `/v1/reveals` | yes | `{protocol, items: [{kind, value_b, value}]}` (at most 200) returns `{accepted, rejected}` |
| POST | `/v1/rechecks` | yes | `{protocol, day, items: [{id, state}]}` (at most 500) returns `{accepted}` |
| GET | `/v1/network` | yes | the network summary |

`standing` is coarse (`new`, `good`, `low`); the reputation number is never sent.

### Target

```json
{"id": "t_8c1d2e0a11bb", "kind": "ip", "value": "198.51.100.23", "value_b": null,
 "state": "confirmed", "nodes": 1, "countries": 4,
 "first_day": "2026-10-26", "last_day": "2026-10-30",
 "services": ["ssh", "telnet"], "activity": ["login", "command", "download"],
 "tags": ["mirai"], "families": ["mirai"],
 "reported_day": null, "taken_down_day": null}
```

- `kind` is `ip`, `url`, `domain`, `sha256`, `c2_ip` or `c2_domain`.
- `value` is null for a blinded kind that is not revealed yet.
- `nodes` is a bucket: `0` is 5 to 9 nodes, `1` is 10 to 24, `2` is 25 or more.
- `countries` is null below 3.
- `state` is `confirmed`, `reported`, `taken_down`, `disputed` or `expired`.
- The cursor is opaque. `recheck` lists confirmed or reported targets the node is asked to check
  (at most 50 per pull).
- A target never carries a node id, a fingerprint or a pseudonym.

### Observation batch

```json
{
  "protocol": "spn/1",
  "batch_id": "AAECAwQFBgcICQoLDA0ODw",
  "day": "2026-10-30",
  "sources": [
    {"ip": "198.51.100.23", "services": ["ssh"], "activity": ["login", "command", "download"],
     "tags": ["mirai"], "sessions": 1, "attempts": 3}
  ],
  "payloads": [
    {"url_b": "<64 hex>", "host_ip": "198.51.100.9", "host_b": null,
     "sha256": "<64 hex>", "family": "mirai", "file_type": "elf-arm", "fetched": true}
  ],
  "c2": [
    {"ip": "198.51.100.50", "domain_b": null, "port": 23, "family": "mirai", "via_sha256": "<64 hex>"}
  ],
  "files": [
    {"sha256": "<64 hex>", "family": "mirai", "file_type": "elf-arm"}
  ],
  "pad": "    "
}
```

- Caps: sources 5000, payloads 1000, c2 1000, files 1000.
- `sessions` and `attempts` are buckets: `0` is 0 or 1, `1` is 2 to 9, `2` is 10 to 99, `3` is 100 to
  999, `4` is 1000 or more.
- `day` must be closed (earlier than the hub's UTC date) and at most 3 days old.
- `batch_id` is 16 random bytes in base64url. A second batch with the same `batch_id` answers
  `duplicate: true` and changes nothing. A different `batch_id` for a day already submitted is
  `invalid_payload`. One batch per node and day.
- A payload has exactly one of `host_ip` and `host_b`; a fetched payload has its `sha256`. A C2
  entry has exactly one of `ip` and `domain_b`.
- Every list holds distinct entries (duplicates are refused).
- Addresses are global unicast IPv4 or IPv6. Documentation ranges are accepted only by a hub test
  overlay (`HUB_ALLOW_DOCUMENTATION=1`).
- Tags outside the allow-list are dropped. Families and file types outside their lists are
  refused. The field `credentials` is reserved and refused in v1.

## Blinding

`value_b = lowercase hex sha256("spn/1|" + kind + "|" + canonical(value))`, where `kind` is `url`
or `domain`.

- **url.** Scheme and host lowercased; the host is converted with the IDNA codec of the Python
  standard library; the default port (80, 443, 21) removed; the fragment removed. Path and query are
  kept byte for byte (an empty path stays empty). User information, spaces and control characters
  make the URL invalid. IPv4 and IPv6 literals are normalised.
- **domain.** Lowercase IDNA, no trailing dot, labels of letters, digits, `-` and `_`. An IP
  address is not a domain.

The hub counts nodes per `value_b`. When a blinded value is confirmed, the hub lists it in
`reveal`; a node that has the clear value sends it to `/v1/reveals`. The hub checks that the value
blinds to `value_b` before it stores it.

## Proof of work

At enrolment, find `pow_nonce` (1 to 16 bytes, sent as base64url) such that
`sha256(challenge || pubkey || pow_nonce)` has at least `difficulty` leading zero bits, where
`challenge` and `pubkey` are the raw 32-byte values. The reference solver counts from zero with an
8-byte big-endian nonce. The default difficulty is 27; the hub raises it by one bit while daily
enrolments exceed its soft cap.

## Versioning

`protocol` is in every body and the path starts with `/v1`. A receiver rejects unknown fields, so
an additive field goes into the hub first, then into nodes. A breaking change is `spn/2` under
`/v2`; the hub serves both for at least 6 months and lists them in `/v1/info`.

## Golden test vectors

`netproto/tests/vectors.json` holds fixed test keys (never used anywhere else), a timestamp, a
nonce and, for each case, the input, the canonical string and the expected signature. Ed25519
signatures are deterministic, so an implementation must reproduce them byte for byte. The file also
covers response signatures, URL and domain blinding (IDNA, default ports, fragments, IPv6) and a
proof of work. A sample:

```
node seed (hex)  000102...1f           node_key  A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
hub seed  (hex)  202122...3f           hub_key   Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc
timestamp 1790000000                   nonce     AAECAwQFBgcICQoLDA0ODw

GET /v1/info, empty body, canonical string:
  SPN1-REQ\nGET\n/v1/info\n1790000000\nAAECAwQFBgcICQoLDA0ODw\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  signature  6SmwSsSm-sIfEpE7-Wrhp7An2EATs7mFefPStH8OO6Nicc6x3CSiIYUX-aG9EzbpvMEd7bmvPjwXxcRx2VFlBg

Response 200 {"deleted":true} to that request, canonical string:
  SPN1-RESP\nGET\n/v1/info\nA6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg\nAAECAwQFBgcICQoLDA0ODw\n5192f07d3c54a1bbc411373a191bde77ed07c5bd9edc0b2ccae5f333ea312060\n200\n1b70b1c98c544d975c39049311ab1d24ed1d87aedc2874bdc946d39bd421b4b8
  signature  dqYMJ9yk6N8qpc-CsuPJnq-xAAKF3B4vfwuzXwxC9kHafEMHGakhnRjei9dWrgHz6cv9bDaZ0dfh_hrWDvRyDA

Blinding: HTTP://Example.ORG:80/a/B?x=1&y=%2F#frag
  canonical  http://example.org/a/B?x=1&y=%2F
  value_b    bd0e11a8735313cbd7659a02a98e97e49514b2a2c696eec46e9d37286755399b
```
