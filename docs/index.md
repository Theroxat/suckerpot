# SuckerPot

SuckerPot is a self-hosted honeypot with a dashboard that makes internet attacks easy to read. A few fake services (sensors) take the attacks. Each attack becomes an event. The events are enriched, tagged and stored. One dashboard shows what happened, as a story you can follow.

Everything runs in Docker Compose on one host.

> **Status: early development.** Built: the event pipeline, the API and live feed, the SSH, RDP and Telnet sensors, enrichment and tagging, the host firewall template, dashboard login, and the dashboard pages (Live, Overview, Attacks, Session detail, Attackers, Trends, Malware). In progress: the web sensor (under security review) and milestone M9 (seven more sensors: Redis, Docker, MySQL, MSSQL, ADB, SMB and SIP, which bring the total to eleven). Also built: retention and the database disk guard. Each page says clearly what is built and what is planned.

```{warning}
SuckerPot is built to be attacked. Deploy it only on a dedicated, isolated machine that you are ready to lose. Read [Getting started](getting-started.md) before you install it.
```

```{toctree}
:maxdepth: 1
:caption: User guide

getting-started
deployment
demo-data
ui
```

```{toctree}
:maxdepth: 2
:caption: Sensors

sensors/index
```

```{toctree}
:maxdepth: 1
:caption: Reference

ARCHITECTURE
configuration
event-schema
api
retention
SECURITY
```

```{toctree}
:maxdepth: 1
:caption: Project

development
ROADMAP
PROGRESS
```
