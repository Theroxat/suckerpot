# Selfhostr

Selfhostr is a self-hosted honeypot with a dashboard that makes internet attacks easy to read. A few fake services (sensors) take the attacks. Each attack becomes an event. The events are enriched, tagged and stored. One dashboard shows what happened, as a story you can follow.

Selfhostr was called SuckerPot; technical names (packages, volumes, environment variables) keep the `suckerpot` prefix.

Everything runs in Docker Compose on one host.

> **Status: v0.2.0.** Twelve sensors, enrichment and tagging, and a dashboard organised in three spaces (Observe, Understand, Defend) plus Settings. The new analysis features are off until you turn them on. See the [roadmap](ROADMAP.md).

```{warning}
Selfhostr is built to be attacked. Deploy it only on a dedicated, isolated machine that you are ready to lose. Read [Getting started](getting-started.md) before you install it.
```

```{toctree}
:maxdepth: 1
:caption: User guide

getting-started
install
participate
updates
deployment
demo-data
ui
defend
replies
takedowns
network
feeds
api-keys
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
network-protocol
SECURITY
design/m21
design/m22
design/m23
design/m24
design/m25
design/m26
design/m27
design/m28
design/m29
design/m30
design/m32
```

```{toctree}
:maxdepth: 1
:caption: Project

development
ROADMAP
PROGRESS
```
