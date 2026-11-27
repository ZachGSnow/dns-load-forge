DNS Load Forge {version} for Windows
=====================================

Double-click dnsloadforge.exe: the dashboard opens in your browser, aimed at a
simulated filtering appliance so everything can be tried safely. Keep the
window it opens; closing it stops the tool.

To test your own filter, open a terminal in this folder and run, for example:

    .\dnsloadforge.exe --server 10.0.0.10 --qps 1000 --duration 120
    .\dnsloadforge.exe checks --server 10.0.0.10
    .\dnsloadforge.exe capacity --server 10.0.0.10 --max-qps 20000
    .\dnsloadforge.exe --help

or copy targets.example.json to targets.json, describe your filter in it, and
double-click again: it appears in the dashboard's list of targets.

The first start downloads the public domain lists (about 40 MB) into
lists\cache in this folder; after that the tool works offline. The run history
is kept in runs\. Keep this folder somewhere you can write to, not in Program
Files. To keep your lists and history when you upgrade, copy those two folders
into the new version's folder.

This build is not code-signed, so Windows SmartScreen may warn the first time
you start it. Check the download before you do, in PowerShell:

    Get-FileHash DNS-Load-Forge-{version}-windows-x64.zip
        (compare with SHA256SUMS on the release page)
    gh attestation verify DNS-Load-Forge-{version}-windows-x64.zip --repo ZachGSnow/dns-load-forge
        (proves GitHub Actions built it from the published source)

On a PC with Smart App Control turned on, Windows blocks unsigned programs
outright; run the Python version there instead (see the README on GitHub).

Responsible use: this sends real DNS traffic, including lookups of malware and
phishing domains. Only test infrastructure you own or are authorised to test.

Documentation: https://github.com/ZachGSnow/dns-load-forge
Licence: MIT (LICENSE). Python's licence: PYTHON-LICENSE.txt. The libraries in
the dashboard: _internal\dnsloadforge\dashboard\THIRD_PARTY_NOTICES.txt
