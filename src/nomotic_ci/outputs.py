"""Set GitHub Action outputs using the GITHUB_OUTPUT file."""

from __future__ import annotations

import os


def set_output(name: str, value: str) -> None:
    """Write a key=value pair to the $GITHUB_OUTPUT file.

    In GitHub Actions, this is how composite/docker actions expose outputs.
    Outside of Actions (e.g., in tests), this is a no-op.
    """
    output_file = os.environ.get("GITHUB_OUTPUT", "")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")
