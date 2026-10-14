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
* **The dashboard is one file with no build step.** Colours are CSS variables, strings are
  inserted with `textContent`, never `innerHTML`.
* **Scoring changes are easy to get subtly wrong.** A mis-scored category makes a healthy
  filter look broken. Say in the pull request what real resolver behaviour motivated it.
