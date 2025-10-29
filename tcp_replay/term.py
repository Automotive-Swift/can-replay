from __future__ import annotations

import os
import sys


class Colors:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def want_color(force: bool | None = None) -> bool:
    if force is True:
        return True
    if force is False:
        return False
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class VLogger:
    def __init__(self, verbose: bool = False, color: bool | None = None):
        self.verbose = verbose
        self.color_enabled = want_color(color)

    def _c(self, text: str, color: str) -> str:
        if not self.color_enabled:
            return text
        return f"{color}{text}{Colors.RESET}"

    def info(self, msg: str):
        if self.verbose:
            print(msg)

    def ok(self, msg: str):
        self.info(self._c(msg, Colors.GREEN))

    def warn(self, msg: str):
        self.info(self._c(msg, Colors.YELLOW))

    def err(self, msg: str):
        self.info(self._c(msg, Colors.RED))

    def note(self, msg: str):
        self.info(self._c(msg, Colors.CYAN))

