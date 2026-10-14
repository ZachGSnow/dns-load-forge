"""DNS Load Forge -- simulate an office's DNS traffic and judge the filter.

Dependency-free by design: this package must run on a freshly imaged Windows box
with nothing but Python, because the machine that can reach the appliance under
test is usually not the machine with a package manager pointed at the internet.

Typical use::

    python -m dnsloadforge.domainlist --refresh     # once, while online
    python -m dnsloadforge --server 10.0.0.10       # vet the appliance

See ``README.md`` for the operator's guide and ``ARCHITECTURE.md`` for how the
pieces fit together.
"""

from __future__ import annotations

__version__ = "1.1.0"

__all__ = ["__version__", "main"]


def main(argv: list[str] | None = None) -> int:
    """Entry point, resolved lazily so importing the package stays cheap."""
    from .cli import main as _main

    return _main(argv)
