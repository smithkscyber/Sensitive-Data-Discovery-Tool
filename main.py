"""CLI entry point for the Sensitive Data Discovery Tool.

Scanning is wired up in Phase 7, once the detectors, parsers, and reporting
pipeline exist. For now this only confirms the project is installed and
runnable:

    python main.py
"""

import sys


def main() -> int:
    print("Sensitive Data Discovery Tool — project scaffold in place.")
    print("Scanning is not implemented yet (see Phase 7 of the build plan).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
