"""WVS web console — a thin Flask frontend over the existing scan engine.

Run from the project root:

    python -m web.app
    #  or
    python web/app.py

Then open http://127.0.0.1:5000 in a browser.

This UI reuses scanner.main.run_scan() directly, so it stays in lock-step
with the CLI: same modules, same findings, same risk score.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import sys
from argparse import Namespace

# Make the project root importable no matter how this file is launched.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from flask import Flask, render_template, request  # noqa: E402

from scanner.main import ALL_MODULES, run_scan  # noqa: E402

app = Flask(__name__)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _as_float(value: str, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        all_modules=ALL_MODULES,
        selected_modules=ALL_MODULES,
        form={"target": "", "max_pages": 40, "timeout": 10, "delay": 0},
        result=None,
        log="",
        error=None,
    )


@app.route("/scan", methods=["POST"])
def scan():
    target = (request.form.get("target") or "").strip()
    selected = request.form.getlist("modules") or list(ALL_MODULES)
    authorized = request.form.get("authorize") == "on"

    form = {
        "target": target,
        "max_pages": _as_int(request.form.get("max_pages"), 40),
        "timeout": _as_float(request.form.get("timeout"), 10.0),
        "delay": _as_float(request.form.get("delay"), 0.0),
    }

    def _render(result=None, log="", error=None):
        return render_template(
            "index.html",
            all_modules=ALL_MODULES,
            selected_modules=selected,
            form=form,
            result=result,
            log=log,
            error=error,
        )

    # --- Guard rails (mirror the CLI's checks) ---
    if not target.startswith(("http://", "https://")):
        return _render(error="Target must start with http:// or https://")
    if not authorized:
        return _render(
            error="Authorization required. Confirm you own or have written "
            "permission to scan this target before launching."
        )

    ns = Namespace(
        target=target,
        modules=",".join(selected),
        max_pages=form["max_pages"],
        timeout=form["timeout"],
        delay=form["delay"],
        no_verify_tls=request.form.get("no_verify_tls") == "on",
    )

    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            result = run_scan(ns)
    except Exception as exc:  # surface engine errors in the console, don't 500
        log = _strip_ansi(buf.getvalue())
        return _render(error=f"Scan failed: {exc.__class__.__name__}: {exc}", log=log)

    log = _strip_ansi(buf.getvalue())
    return _render(result=result, log=log)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
