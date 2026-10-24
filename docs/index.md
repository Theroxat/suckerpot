# SuckerPot

SuckerPot is a self-hosted honeypot with a dashboard that makes internet attacks easy to read. A few fake services (sensors) take the attacks. Each attack becomes an event. The events are enriched, tagged and stored. One dashboard shows what happened, as a story you can follow.

Everything runs in Docker Compose on one host.

> **Status: early development.** Milestone M1 (the event pipeline, the API and the live feed) is built. The sensors, enrichment and the full web UI are planned. Each page says clearly what is built and what is planned.

```{warning}
SuckerPot is built to be attacked. Deploy it only on a dedicated, isolated machine that you are ready to lose. Read [Getting started](getting-started.md) before you install it.
```

```{toctree}
:maxdepth: 1
:caption: User guide

getting-started
deployment
demo-data
```

```{toctree}
:maxdepth: 1
:caption: Reference

ARCHITECTURE
configuration
event-schema
api
SECURITY
```

```{toctree}
:maxdepth: 1
:caption: Project

development
ROADMAP
PROGRESS
```
