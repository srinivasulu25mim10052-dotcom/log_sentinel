#!/usr/bin/env python3
"""
LogSentinel Application Entrypoint.

Python Essentials Demonstrated:
- Standard script entrypoint guard: if __name__ == "__main__"
- sys.exit with exit code propagation
- Clean module execution
"""

import sys
from sentinel.cli import main

if __name__ == "__main__":
    sys.exit(main())
