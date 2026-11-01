# Selfhostr public site

The one-page website of the project, served at https://selfhostr.io/. Plain HTML, CSS and JavaScript: no framework, no build step, no CDN, no trackers, no analytics, no third-party requests. Fonts (Inter, JetBrains Mono) are self-hosted under `public/fonts/` with their licences.

It is independent of the honeypot stack: its own Dockerfile and compose file, nothing shared with the root `docker-compose.yml`.

## Layout

| Path | What it is |
| --- | --- |
| `public/` | The static files. This is all that is served |
| `public/js/theme.js` | Applies the stored or OS theme before first paint (loaded in `<head>`) |
| `public/js/site.js` | Theme toggle, copy buttons, the hero replay. `?motion=off` shows the final state at once (screenshots); `prefers-reduced-motion` does the same |
| `nginx.conf` | Server config: security headers (strict CSP, no inline script or style), gzip, cache headers, `server_tokens off`, access logs off, GET and HEAD only, `/healthz` |
| `Dockerfile` | Pinned `nginxinc/nginx-unprivileged`, non-root, port 8080, healthcheck |
| `compose.yml` | Standalone compose file: one service `site`, read-only with a tmpfs for `/tmp`, all capabilities dropped, `no-new-privileges`, memory, CPU and pids limits |

## Build and run

```bash
docker compose -f site/compose.yml -p selfhostr-site up -d --build
```

The site listens on host port `SITE_PORT` (default `8141`). Put a TLS reverse proxy or a tunnel in front of it; the container itself only speaks HTTP. Check it with `curl -I http://127.0.0.1:8141/`.

For a throwaway test next to a running copy, use another project name and port, for example `SITE_PORT=18141 docker compose -f site/compose.yml -p sitetest up -d --build`, then `docker compose -f site/compose.yml -p sitetest down`.

## Move it to another server

The site has no volumes and no state. Copy the `site/` directory (or clone the repository), then run the same command on the new host. Point the proxy or tunnel at the new host's `SITE_PORT`, and stop the old copy with `docker compose -f site/compose.yml -p selfhostr-site down`.

## GitHub Pages

`.github/workflows/pages.yml` also publishes `public/` to GitHub Pages, with the mock-data dashboard at `demo/`. The page does not link to `demo/`, because the same files are served at selfhostr.io where there is no demo. Response headers (CSP and the rest) come from `nginx.conf`, so they apply only to the self-hosted copy.

## Content rules

- Every address on the page is from a documentation range (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), every ASN from `AS64496`–`AS64511`, every name is made up.
- Features that are not built yet are marked "coming".
- The "Source code" links are a `#source` placeholder until the repository location is published (TODO in `public/index.html`).
