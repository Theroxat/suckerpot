---
name: Bug report
about: Report something that does not work
title: '[BUG] '
labels: 'bug'
assignees: ''
---

**What happened**
What you did, what you expected, what you got.

**Steps to reproduce**
1. `docker compose up -d --build --wait`
2. ...

**Affected part**
- [ ] A sensor (ssh, telnet, web, rdp)
- [ ] Ingest
- [ ] API
- [ ] Dashboard
- [ ] Docker Compose or deployment
- [ ] Docs

**Version**
Commit hash or release, and `docker compose version`.

**Logs**
`docker compose logs --tail 100 <service>`. Redact secrets, real IP addresses and any captured attacker data.

If this is a security problem, do not open an issue: see [SECURITY.md](../../SECURITY.md).
