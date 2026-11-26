# Contributing

```bash
python -m unittest discover -s tests -t tests -v      # about 90 seconds, no network needed
```

* **No runtime dependencies.** The tool has to run on a freshly imaged Windows machine with
  nothing but Python 3.10+. Please do not add a third-party import to `src/`.
* **Tests drive real UDP.** The most valuable tests send real packets at the built-in mock
  appliance and assert on the verdict. A change to scoring needs a test that would have
  failed before it.
* **Read `ARCHITECTURE.md` first.** Several decisions that look odd (sequential comparison
  runs, one aggregator with per-shard counters, `received` excluding timeouts) are there for
  a reason, and the file says why.
* **Scoring changes are easy to get subtly wrong.** A mis-scored category makes a healthy
  filter look broken. Say in the pull request what real resolver behaviour motivated it.
* **Plain ASCII in every file.** Hyphens, straight quotes, `->`, `...`. Text the dashboard
  renders may use real typography, written as an HTML entity in JSX (`&hellip;`), so the
  source stays ASCII; the build escapes anything else.

## Changing the dashboard

The dashboard is a React app (Tailwind CSS and [shadcn/ui](https://ui.shadcn.com)
components) in `web/`. Vite builds it into one self-contained page,
`src/dnsloadforge/dashboard/index.html`, which is committed: the Python package serves it
as a file and never needs Node. You need Node 24 only to change it.

```bash
python -m dnsloadforge serve --mock      # terminal 1: a server with something to show
cd web
npm ci
npm run dev                              # terminal 2: http://localhost:5173, proxied to :8787
npm run check                            # lint, unit tests, type-check and build
```

* Open the dev page with `?demo=1` to work without a server at all.
* **Commit the built page with its source.** CI rebuilds it and fails when the committed
  copy differs, so a Dependabot bump to a bundled library needs `npm run build` committed
  on its branch before it can merge.
* The page must make no request beyond its own server; the build checks for external
  references and the server's Content-Security-Policy enforces it.
* Values from the network are rendered as React text, never as HTML.
* Colours are CSS variables in `web/src/index.css`, one block per theme. `npm test` checks
  every theme's text and status colours for 4.5:1 contrast.
* `node scripts/screenshots.mjs` (in `web/`) captures the pages from a running server, for
  the README and for checking a change by eye.
