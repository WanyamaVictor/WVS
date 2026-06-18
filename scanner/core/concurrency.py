"""Small concurrency helper shared by scanner modules.

Active modules (SQLi, XSS) fan a function out over many injection points. This
runs them on a thread pool with a wall-clock budget, so a slow or pathological
target (e.g. an app that takes ~1s per POST and has hundreds of form fields)
can never blow the scan up into minutes. Falls back to sequential when a request
delay is configured (politeness) or only one worker is allowed.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout

# Caps that bound the injectable surface up front.
MAX_FIELDS_PER_FORM = 15      # only fuzz the first N fields of any one form
MAX_INJECTION_POINTS = 250    # ceiling on injection points per module
ACTIVE_BUDGET_SECONDS = 25.0  # wall-clock budget per active module


def parallel_map(fn, items, workers: int = 8, sequential: bool = False) -> list:
    """Apply ``fn`` to each item, concurrently unless ``sequential``. In order."""
    items = list(items)
    if not items:
        return []
    if sequential or workers <= 1:
        return [fn(item) for item in items]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))


def budgeted_map(fn, items, workers: int = 8, deadline_s: float = ACTIVE_BUDGET_SECONDS,
                 sequential: bool = False):
    """Apply ``fn`` over items but stop once ``deadline_s`` wall-clock elapses.

    Returns ``(results, skipped)`` where ``skipped`` is how many items were not
    processed because the time budget ran out. Queued-but-unstarted work is
    cancelled; at most ``workers`` in-flight requests finish after the deadline.
    """
    items = list(items)
    if not items:
        return [], 0

    start = time.perf_counter()

    if sequential or workers <= 1:
        results = []
        for i, item in enumerate(items):
            if time.perf_counter() - start > deadline_s:
                return results, len(items) - i
            results.append(fn(item))
        return results, 0

    pool = ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(fn, item) for item in items]
    results, processed = [], 0
    try:
        for fut in futures:
            remaining = deadline_s - (time.perf_counter() - start)
            if remaining <= 0:
                break
            try:
                results.append(fut.result(timeout=remaining))
                processed += 1
            except FuturesTimeout:
                break
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results, len(items) - processed
