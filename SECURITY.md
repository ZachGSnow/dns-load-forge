# Security and responsible use

## What this tool does to the network

DNS Load Forge sends real DNS queries, including queries for names on public malware,
phishing and adult block lists. It only *asks* for those names; it never connects to the
addresses that come back. Even so:

* Security monitoring that logs DNS lookups may alert on the block-listed names, the
  algorithmic-looking `.invalid` probes, or the sheer query volume from one host. Tell
  whoever watches your network before you run it.
* `checks` sends single queries to public resolvers (Google, Cloudflare, Quad9) and to the
  vendors' published test domains, and opens TCP connections to their DoH/DoT ports
  without sending anything, to see whether the network lets clients around the filter.
  `--no-network` leaves those out.
* A resolver you do not own is somebody else's infrastructure. Public targets are held to
  100 queries per second unless you pass `--allow-public-target`, whether they are named
  by address or, for DNS over HTTPS and TLS, by the name on their certificate. Only test
  services you are authorised to test, and ask a vendor before pushing hard on a shared
  service.
* `capacity` raises the load until the target breaks one of your limits. On a resolver in
  production that is the outage you are measuring for, so run it in a change window,
  against a target you are authorised to load, with `--max-qps` set to what you are
  prepared to send. The public-resolver guard judges that highest rate.
* Over DNS over TLS and HTTPS the server's certificate is checked against the system's
  roots, or the CAs in `--ca-file`. `--insecure` turns the check off: the traffic is still
  encrypted, but the server is not authenticated, so keep it for a lab appliance whose
  certificate nothing trusts. DoH requests carry `User-Agent: DNS-Load-Forge/<version>`,
  so the appliance's logs say what the traffic is, and DoH over plain HTTP is accepted only
  for an address on this machine (the mock).

## The dashboard

The dashboard can start and stop load tests and **has no login**, so it is built to be
reachable only from the machine that runs it:

* It binds to `127.0.0.1`. Binding anywhere else requires `--allow-remote-dashboard`, and
  you then own the exposure.
* On loopback it refuses any request whose `Host` is not localhost (DNS rebinding), any
  cross-origin or cross-site write, and any write that is not JSON (cross-site form posts).
* The page is served with a Content-Security-Policy that admits only its own inline scripts
  (by hash) and lets it talk to this server and nothing else, and it refuses to be framed
  by another site, so its Start button cannot be clickjacked.
* Everything the page renders from the network is inserted as text, never markup.
* The report at `/report` is served with a policy that admits no script at all, and holds
  only the current session's runs: saved runs from earlier sessions, which may be another
  client's, are left out. The run history itself (`history.jsonl`) names the targets you
  tested; `--no-history` keeps none, and *Clear* on the Compare page deletes it.

If you put it behind a reverse proxy, add authentication there.

## Reporting a problem

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/ZachGSnow/dns-load-forge/security/advisories/new)
rather than a public issue. You can expect an acknowledgement within 7 days. Fixes ship as
a patch release. Only the latest release is supported.

## Secrets

This repository contains no credentials. Your own targets live in a gitignored
`targets.json` created from `targets.example.json`. Every push is scanned with
[gitleaks](https://github.com/gitleaks/gitleaks).
