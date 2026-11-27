"""The Windows executable's entry point: the same as ``python -m dnsloadforge``.

Double-clicked from Explorer, ``main`` serves the dashboard on the built-in mock
and opens it; from a terminal it is the command line as documented.
"""

import sys

from dnsloadforge.cli import main

if __name__ == "__main__":
    sys.exit(main())
