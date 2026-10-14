"""Hand-curated domain lists that ship with the tool.

Everything else in ``domainlist.py`` comes from a GitHub list that may be
unreachable, rate-limited or retired.  These two lists never need the network,
and they are the highest-value test cases the tool has, so they are committed
here instead of fetched:

``ENTERPRISE_DOMAINS``
    Names whose failure to resolve means *the office is broken*.  A filtering
    appliance that sinkholes ``login.microsoftonline.com`` or a ``_ldap._tcp``
    SRV record has caused a real outage, and the operator needs that surfaced
    as a false positive, not buried in a pile of ad domains.  This list is
    deliberately weighted towards (a) Microsoft 365 / Entra sign-in and update
    endpoints, because they are the classic casualty of over-eager DNS
    filtering, (b) internal Active Directory names including SRV service
    records and reverse (PTR) names, since SRV is a frequent filter gap, and
    (c) the big CDN/pkg-registry hostnames a developer desktop cannot work
    without.

``BORDERLINE_DOMAINS``
    The grey zone: trackers, telemetry, analytics and advertising that a naive
    filter blocks and that a careless one allows.  They are reported in their
    own category and never counted as a pass or a failure, because there is no
    single correct answer -- an enterprise may legitimately want DoubleClick
    blocked and ``clarity.ms`` allowed.  Their purpose is to *describe* what the
    appliance does with the ambiguous middle of the internet, which is where
    filter policies actually differ.

Because these lists are assertions about intent, they deliberately win over the
fetched block lists when a name appears in both (StevenBlack's unified list
contains Microsoft telemetry hostnames that also appear here).  See
``domainlist._resolve_overlaps`` for how that tie is broken.
"""

from __future__ import annotations

from .spec import Category

__all__ = [
    "CURATED_SOURCE",
    "ENTERPRISE_DOMAINS",
    "BORDERLINE_DOMAINS",
    "CURATED_BY_CATEGORY",
]

#: Recorded as the ``source`` of these pools so the summary can say where they
#: came from.
CURATED_SOURCE = "curated"

#: Identity, update, mail and collaboration planes.  Breaking any of these
#: breaks sign-in or patching for the whole estate.
ENTERPRISE_DOMAINS: list[str] = [
    # --- Microsoft 365 / Entra ID sign-in -----------------------------------
    "login.microsoftonline.com",
    "login.microsoftonline.us",
    "login.microsoft.com",
    "login.live.com",
    "login.windows.net",
    "graph.microsoft.com",
    "graph.windows.net",
    "aadcdn.msauth.net",
    "aadcdn.msftauth.net",
    "autologon.microsoftazuread-sso.com",
    "enterpriseregistration.windows.net",
    "enterpriseenrollment.manage.microsoft.com",
    "manage.microsoft.com",
    # --- Microsoft 365 mail / Office web apps --------------------------------
    "outlook.office365.com",
    "outlook.office.com",
    "outlook.office.net",
    "smtp.office365.com",
    "imap.office365.com",
    "pop.office365.com",
    "attachments.office.net",
    "substrate.office.com",
    "www.office.com",
    "office.com",
    "officeapps.live.com",
    "excel.officeapps.live.com",
    "word-edit.officeapps.live.com",
    "cdn.office.net",
    "res.cdn.office.net",
    # --- Teams / collaboration ----------------------------------------------
    "teams.microsoft.com",
    "teams.microsoft.us",
    "config.teams.microsoft.com",
    "presence.teams.microsoft.com",
    "meet.google.com",
    "slack.com",
    "app.slack.com",
    "zoom.us",
    "us02web.zoom.us",
    "zoomgov.com",
    "webex.com",
    "salesforce.com",
    "login.salesforce.com",
    "my.salesforce.com",
    "docusign.net",
    "docusign.com",
    # --- Windows Update / patching -------------------------------------------
    "windowsupdate.com",
    "windowsupdate.microsoft.com",
    "update.microsoft.com",
    "download.windowsupdate.com",
    "catalog.update.microsoft.com",
    "wus2.update.microsoft.com",
    "definitionupdates.microsoft.com",
    "ctldl.windowsupdate.com",
    # --- Certificates, CRL and OCSP (blocking these breaks TLS estate-wide) ---
    "crl.microsoft.com",
    "ocsp.digicert.com",
    "ocsp.apple.com",
    "crl.apple.com",
    "ocsp.pki.goog",
    # --- Endpoint management --------------------------------------------------
    "dm.microsoft.com",
    "v10.events.data.microsoft.com",
    "v10c.events.data.microsoft.com",
    "settings-win.data.microsoft.com",
    # --- Internal Active Directory (lower-case FQDN style) -------------------
    "corp.local",
    "dc01.corp.local",
    "dc02.corp.local",
    "fs01.corp.local",
    "fs02.corp.local",
    "print01.corp.local",
    "print02.corp.local",
    "intranet.corp.local",
    "sharepoint.corp.local",
    "mail.corp.local",
    "autodiscover.corp.local",
    "lyncdiscover.corp.local",
    "sip.corp.local",
    "wsus01.corp.local",
    "sccm01.corp.local",
    "time.corp.local",
    # --- AD service location: SRV lookups are a very common filter gap --------
    "_ldap._tcp.corp.local",
    "_ldap._tcp.dc._msdcs.corp.local",
    "_ldap._tcp.Default-First-Site-Name._sites.corp.local",
    "_kerberos._tcp.corp.local",
    "_kpasswd._tcp.corp.local",
    "_gc._tcp.corp.local",
    "_sip._tcp.corp.local",
    "_sip._udp.corp.local",
    "_sips._tcp.corp.local",
    "_sipfederationtls._tcp.corp.local",
    "_autodiscover._tcp.corp.local",
    "_xmpp-server._tcp.corp.local",
    "_https._tcp.corp.local",
    "_ntp._udp.corp.local",
    # --- Reverse lookups (PTR) for the workstation and printer subnets -------
    "7.106.1.10.in-addr.arpa",
    "1.2.3.10.in-addr.arpa",
    "10.20.30.10.in-addr.arpa",
    # --- Identity / SSO / ITSM ------------------------------------------------
    "okta.com",
    "login.okta.com",
    "atlassian.net",
    "auth.atlassian.com",
    "api.atlassian.com",
    "workday.com",
    "servicenow.com",
    "service-now.com",
    "citrix.com",
    "box.com",
    "account.box.com",
    "dropbox.com",
    "www.dropbox.com",
    "onedrive.live.com",
    # --- Developer / package registries and CDNs -----------------------------
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "nuget.org",
    "api.nuget.org",
    "crates.io",
    "docker.io",
    "registry-1.docker.io",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "cdnjs.cloudflare.com",
    "googleapis.com",
    "www.googleapis.com",
    "storage.googleapis.com",
    "firebaseio.com",
    "gstatic.com",
    "www.gstatic.com",
    # --- Cloud, TLS and CDN infrastructure -----------------------------------
    "amazonaws.com",
    "s3.amazonaws.com",
    "ec2.amazonaws.com",
    "aws.amazon.com",
    "cloudflare.com",
    "www.cloudflare.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "akamai.net",
    "akamaiedge.net",
    "akamaitechnologies.com",
    "edgekey.net",
    "cloudfront.net",
    "fastly.net",
    "fastlylb.net",
    "azureedge.net",
    "azurefd.net",
    "trafficmanager.net",
    "windows.net",
    "blob.core.windows.net",
    "servicebus.windows.net",
    "apple.com",
    "www.apple.com",
    "gs.apple.com",
    "itunes.apple.com",
    "push.apple.com",
    "mzstatic.com",
]

#: Analysts, advertising and telemetry.  Blocking some of these is a legitimate
#: policy choice; blocking others silently breaks page loads and product
#: telemetry.  Reported, never graded.
BORDERLINE_DOMAINS: list[str] = [
    # --- Web analytics --------------------------------------------------------
    "google-analytics.com",
    "www.google-analytics.com",
    "ssl.google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "www.googletagmanager.com",
    "googletagservices.com",
    "app-measurement.com",
    "stats.g.doubleclick.net",
    "segment.io",
    "api.segment.io",
    "cdn.segment.com",
    "mixpanel.com",
    "api.mixpanel.com",
    "amplitude.com",
    "api.amplitude.com",
    "heap.io",
    "heapanalytics.com",
    "matomo.cloud",
    "plausible.io",
    # --- Advertising ----------------------------------------------------------
    "doubleclick.net",
    "ad.doubleclick.net",
    "googleads.g.doubleclick.net",
    "pagead2.googlesyndication.com",
    "googlesyndication.com",
    "adservice.google.com",
    "pubads.g.doubleclick.net",
    "ads.linkedin.com",
    "ads.pinterest.com",
    "ads.reddit.com",
    "ads-twitter.com",
    "static.ads-twitter.com",
    "analytics.tiktok.com",
    "business-api.tiktok.com",
    "connect.facebook.net",
    "graph.facebook.com",
    "www.facebook.com",
    "pixel.facebook.com",
    "an.facebook.com",
    # --- Session replay, error and performance monitoring ---------------------
    "hotjar.com",
    "static.hotjar.com",
    "script.hotjar.com",
    "fullstory.com",
    "fs.fullstory.com",
    "logrocket.com",
    "logrocket.io",
    "smartlook.com",
    "cdn.smartlook.com",
    "mouseflow.com",
    "crazyegg.com",
    "bugsnag.com",
    "notify.bugsnag.com",
    "sentry.io",
    "o4504.ingest.sentry.io",
    "browser.sentry-cdn.com",
    "newrelic.com",
    "js-agent.newrelic.com",
    "bam.nr-data.net",
    "datadoghq.com",
    "browser-intake-datadoghq.com",
    "rum.browser-intake-datadoghq.com",
    "appdynamics.com",
    "dynatrace.com",
    "js-cdn.dynatrace.com",
    # --- Product telemetry (Microsoft / Mozilla / Apple) ----------------------
    "clarity.ms",
    "www.clarity.ms",
    "c.clarity.ms",
    "telemetry.microsoft.com",
    "vortex.data.microsoft.com",
    "browser.events.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "settings.data.microsoft.com",
    "self.events.data.microsoft.com",
    "spynet.microsoft.com",
    "telemetry.mozilla.org",
    "incoming.telemetry.mozilla.org",
    "telemetry.apple.com",
    # --- Marketing / CRM / support widgets -----------------------------------
    "hubspot.com",
    "js.hs-scripts.com",
    "hsforms.net",
    "forms.hsforms.com",
    "marketo.net",
    "munchkin.marketo.net",
    "pardot.com",
    "pi.pardot.com",
    "intercom.io",
    "widget.intercom.io",
    "js.intercomcdn.com",
    "drift.com",
    "js.driftt.com",
    "pendo.io",
    "cdn.pendo.io",
    "optimizely.com",
    "cdn.optimizely.com",
    "vwo.com",
    "branch.io",
    "app.link",
    "adjust.com",
    "app.adjust.com",
    "kochava.com",
    "onesignal.com",
    "cdn.onesignal.com",
    "crashlytics.com",
    "firebase-settings.crashlytics.com",
    # --- CDN edges that are called "trackers" by some lists -------------------
    "akamaihd.net",
    "edgecastcdn.net",
    "llnwd.net",
    "stackpathdns.com",
    "cachefly.net",
    "bunnycdn.com",
    "use.typekit.net",
    "typekit.net",
]

#: The two curated pools keyed by category value, for easy iteration in
#: ``domainlist.py``.
CURATED_BY_CATEGORY: dict[str, list[str]] = {
    Category.ENTERPRISE.value: ENTERPRISE_DOMAINS,
    Category.BORDERLINE.value: BORDERLINE_DOMAINS,
}
