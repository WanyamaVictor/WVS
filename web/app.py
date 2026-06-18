"""WVS web console — Flask frontend over the scan engine.

Run from the project root:

    python -m web.app          # or:  python web/app.py

Then open http://127.0.0.1:5000.

Features
--------
* Live, non-blocking scans streamed to the browser over Server-Sent Events.
* Every scan is persisted to SQLite; browse history, reopen, compare, export.
* Reuses scanner.main.run_scan() so the UI stays in lock-step with the CLI.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import uuid
from argparse import Namespace

# Make the project root importable no matter how this file is launched.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from flask import (  # noqa: E402
    Flask, Response, abort, redirect, render_template, request, url_for,
)

from scanner.core import storage  # noqa: E402
from scanner.core.models import ScanResult, Severity  # noqa: E402
from scanner.main import ALL_MODULES, run_scan  # noqa: E402
from scanner.report import report_generator  # noqa: E402

app = Flask(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


# --------------------------------------------------------------------------- #
# Background scan jobs (in-memory) feeding the SSE stream.
# --------------------------------------------------------------------------- #
class Job:
    def __init__(self) -> None:
        self.queue: "queue.Queue[dict]" = queue.Queue()
        self.status: str = "running"      # running | done | error
        self.scan_id: int | None = None
        self.error: str | None = None


JOBS: dict[str, Job] = {}


def _prune_jobs(keep: int = 20) -> None:
    """Bound memory: drop the oldest finished jobs, keep all running ones."""
    finished = [jid for jid, j in JOBS.items() if j.status != "running"]
    for jid in finished[:-keep] if len(finished) > keep else []:
        JOBS.pop(jid, None)


def _as_float(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _worker(job: Job, ns: Namespace, modules_str: str) -> None:
    """Run the scan in a thread, forwarding progress events to the job queue."""
    try:
        result = run_scan(ns, on_event=job.queue.put)
        scan_id = storage.save_scan(result, modules=modules_str)
        job.scan_id = scan_id
        job.status = "done"
        job.queue.put({
            "type": "complete",
            "scan_id": scan_id,
            "risk_score": result.risk_score,
            "findings": len(result.findings),
        })
    except Exception as exc:  # surface to the client instead of dying silently
        job.error = f"{exc.__class__.__name__}: {exc}"
        job.status = "error"
        job.queue.put({"type": "error", "message": job.error})


def _sort_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: SEV_RANK.get(f.get("severity", "info"), 99))


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def dashboard():
    return render_template(
        "dashboard.html", stats=storage.stats(), severity_order=SEVERITY_ORDER,
    )


@app.route("/console")
def console():
    recent = storage.list_scans(limit=5)
    return render_template(
        "console.html", all_modules=ALL_MODULES, recent=recent,
    )


@app.route("/scan/start", methods=["POST"])
def scan_start():
    target = (request.form.get("target") or "").strip()
    selected = request.form.getlist("modules") or list(ALL_MODULES)
    authorized = request.form.get("authorize") == "on"

    if not target.startswith(("http://", "https://")):
        return {"error": "Target must start with http:// or https://"}, 400
    if not authorized:
        return {"error": "Authorization required. Confirm you own or have written "
                         "permission to scan this target."}, 400

    ns = Namespace(
        target=target,
        modules=",".join(selected),
        max_pages=_as_int(request.form.get("max_pages"), 40),
        timeout=_as_float(request.form.get("timeout"), 10.0),
        delay=_as_float(request.form.get("delay"), 0.0),
        no_verify_tls=request.form.get("no_verify_tls") == "on",
    )

    _prune_jobs()
    job_id = uuid.uuid4().hex
    job = Job()
    JOBS[job_id] = job
    threading.Thread(
        target=_worker, args=(job, ns, ",".join(selected)), daemon=True,
    ).start()
    return {"job_id": job_id, "target": target}


@app.route("/scan/stream/<job_id>")
def scan_stream(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        abort(404)

    def gen():
        # The job is intentionally NOT removed when this stream ends — completion
        # is recorded on the job and also exposed via /scan/status, so a dropped
        # connection during a long scan never loses the result.
        while True:
            try:
                event = job.queue.get(timeout=15)
            except queue.Empty:
                yield ": keepalive\n\n"            # keep the connection from idling out
                if job.status != "running":
                    break
                continue
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") in ("complete", "error"):
                break

    return Response(
        gen(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/scan/status/<job_id>")
def scan_status(job_id: str):
    """Completion fallback the client polls in case the SSE stream drops."""
    job = JOBS.get(job_id)
    if job is None:
        return {"status": "unknown"}, 404
    return {"status": job.status, "scan_id": job.scan_id, "error": job.error}


@app.route("/scan/<int:scan_id>")
def scan_view(scan_id: int):
    scan = storage.get_scan(scan_id)
    if scan is None:
        abort(404)
    scan["findings"] = _sort_findings(scan.get("findings", []))
    return render_template("scan_view.html", scan=scan, severity_order=SEVERITY_ORDER)


@app.route("/history")
def history():
    return render_template("history.html", scans=storage.list_scans())


@app.route("/scan/<int:scan_id>/delete", methods=["POST"])
def scan_delete(scan_id: int):
    storage.delete_scan(scan_id)
    return redirect(url_for("history"))


@app.route("/compare")
def compare():
    a = _as_int(request.args.get("a"), 0)
    b = _as_int(request.args.get("b"), 0)
    diff = storage.compare(a, b)
    if diff is None:
        abort(404)
    for bucket in ("added", "removed", "unchanged"):
        diff[bucket] = _sort_findings(diff[bucket])
    return render_template("compare.html", diff=diff)


@app.route("/scan/<int:scan_id>/export.json")
def export_json(scan_id: int):
    scan = storage.get_scan(scan_id)
    if scan is None:
        abort(404)
    payload = json.dumps(scan, indent=2)
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="wvs-scan-{scan_id}.json"'},
    )


@app.route("/scan/<int:scan_id>/export.html")
def export_html(scan_id: int):
    scan = storage.get_scan(scan_id)
    if scan is None:
        abort(404)
    result = ScanResult.from_dict(scan)
    return Response(
        report_generator.render_html(result),
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="wvs-scan-{scan_id}.html"'},
    )


@app.route("/scan/<int:scan_id>/export.pdf")
def export_pdf(scan_id: int):
    scan = storage.get_scan(scan_id)
    if scan is None:
        abort(404)
    result = ScanResult.from_dict(scan)
    return Response(
        report_generator.render_pdf(result),
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="wvs-scan-{scan_id}.pdf"'},
    )


# --------------------------------------------------------------------------- #
# REST API (JSON) — trigger and fetch scans programmatically.
# --------------------------------------------------------------------------- #
@app.route("/api/health")
def api_health():
    return {"status": "ok", "modules": ALL_MODULES}


@app.route("/api/scans")
def api_list_scans():
    return {"scans": storage.list_scans()}


@app.route("/api/scans/<int:scan_id>")
def api_get_scan(scan_id: int):
    scan = storage.get_scan(scan_id)
    if scan is None:
        return {"error": "scan not found"}, 404
    return scan


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Run a scan synchronously and return the full result. Body is JSON."""
    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    modules = body.get("modules") or list(ALL_MODULES)
    if isinstance(modules, str):
        modules = [m.strip() for m in modules.split(",") if m.strip()]

    if not target.startswith(("http://", "https://")):
        return {"error": "target must start with http:// or https://"}, 400
    if not body.get("authorize"):
        return {"error": "authorize must be true (you confirm permission to scan)"}, 400

    ns = Namespace(
        target=target,
        modules=",".join(modules),
        max_pages=_as_int(body.get("max_pages"), 40),
        timeout=_as_float(body.get("timeout"), 10.0),
        delay=_as_float(body.get("delay"), 0.0),
        no_verify_tls=bool(body.get("no_verify_tls", False)),
        workers=_as_int(body.get("workers"), 8),
    )
    result = run_scan(ns)
    scan_id = storage.save_scan(result, modules=",".join(modules))
    payload = result.to_dict()
    payload["id"] = scan_id
    return {"scan_id": scan_id, "result": payload}


if __name__ == "__main__":
    storage.init_db()
    host = os.environ.get("WVS_HOST", "127.0.0.1")  # set to 0.0.0.0 in Docker
    port = int(os.environ.get("WVS_PORT", "5000"))
    app.run(host=host, port=port, threaded=True, debug=False)
