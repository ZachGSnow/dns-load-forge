# Security and responsible use

## What this tool does to the network

DNS Load Forge sends real DNS queries, including queries for names on public malware,
phishing and adult block lists. It only *asks* for those names; it never connects to the
addresses that come back. Even so:

* Security monitoring that logs DNS lookups may alert on the block-listed names, the
  algorithmic-looking `.invalid` probes, or the sheer query volume from one host. Tell
  whoever watches your network before you run it.
* A resolver you do not own is somebody else's infrastructure. Public targets are held to
  100 queries per second unless you pass `--allow-public-target`. Only test services you
  are authorised to test, and ask a vendor before pushing hard on a shared service.

## The dashboard

The dashboard can start and stop load tests and **has no login**, so it is built to be
reachable only from the machine that runs it:

* It binds to `127.0.0.1`. Binding anywhere else requires `--allow-remote-dashboard`, and
  you then own the exposure.
* On loopback it refuses any request whose `Host` is not localhost (DNS rebinding), any
  cross-origin or cross-site write, and any write that is not JSON (cross-site form posts).
* Everything the page renders from the network is inserted as text, never markup.

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
