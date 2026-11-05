#!/usr/bin/env python3
"""Profile an injected, pinned full-clone verifier without changing its proof.

This is an importable measurement utility, not a controller or CLI. The caller
owns source pins, exclusive use of the verifier module, credentials, lifecycle
locks, snapshot guards, and client closure. There is no filesystem or SDK setup.
Only the verifier module's named functions are temporarily wrapped; an SDK is
never monkeypatched. Function timings are inclusive and must not be summed.
The verifier must join its request workers before returning or raising. Shared
bookkeeping is locked, but SDK calls and response-body I/O are never serialized.

On success, profile_verify_generation returns (the original result, metrics).
On failure, the original exception is re-raised. Pass an empty metrics dictionary
to retain partial measurements on that path. Metrics contain fixed counters and
timings only, never API arguments, keys, versions, payloads, or exception text.
"""
from __future__ import annotations

import functools
import threading
import time
import types


FUNCTIONS = (
    "_baseline_pins", "_lineage", "_get_bytes", "_decode_tables",
    "_validate_stage", "_collect_latest", "_hash_new_sst", "_head_matches",
)
_PROFILE_LOCK = threading.Lock()


class ProfileRefusal(RuntimeError):
    """The supplied profiler interface would exceed its read-only scope."""


def _call_stats(*, cpu=False):
    result = {"calls": 0, "failed_calls": 0, "wall_seconds": 0.0}
    if cpu:
        result["cpu_seconds"] = 0.0
    return result


def _retry_stats():
    return {"responses_with_retry_metadata": 0, "reported_retry_attempts": 0,
            "max_reported_retry_attempts": 0}


def _record_retries(stats, response):
    if not isinstance(response, dict):
        return
    metadata = response.get("ResponseMetadata")
    attempts = metadata.get("RetryAttempts") if isinstance(metadata, dict) else None
    if type(attempts) is int and 0 <= attempts <= 2**31 - 1:
        stats["responses_with_retry_metadata"] += 1
        stats["reported_retry_attempts"] += attempts
        stats["max_reported_retry_attempts"] = max(stats["max_reported_retry_attempts"], attempts)


def _error_retries(stats, error):
    # Optional SDK diagnostics must never replace the original exception.
    try:
        _record_retries(stats, getattr(error, "response", None))
    except BaseException:
        pass


def _record_page_rows(stats, page):
    if isinstance(page, dict):
        for field, counter in (("Versions", "version_rows"), ("DeleteMarkers", "delete_marker_rows")):
            rows = page.get(field)
            if isinstance(rows, (list, tuple)):
                stats[counter] += len(rows)
                stats["latest_" + counter] += sum(
                    isinstance(row, dict) and row.get("IsLatest") is True for row in rows)


def _call(stats, operation, args, kwargs, stats_lock, *, listing=False):
    with stats_lock:
        stats["calls"] += 1
        if listing:
            stats["in_flight"] += 1
            stats["max_in_flight"] = max(stats["max_in_flight"], stats["in_flight"])
    started = time.perf_counter()
    try:
        response = operation(*args, **kwargs)
    except BaseException as error:
        with stats_lock:
            stats["failed_calls"] += 1
            _error_retries(stats, error)
        raise
    else:
        with stats_lock:
            _record_retries(stats, response)
            if listing:
                stats["pages"] += 1
                _record_page_rows(stats, response)
        return response
    finally:
        elapsed = time.perf_counter() - started
        with stats_lock:
            stats["wall_seconds"] += elapsed
            if listing:
                stats["in_flight"] -= 1


class _ReadOnlyProxy:
    def _deny(self, message):
        with self._stats_lock:
            self._metrics["denied_operations"] += 1
        raise ProfileRefusal(message)

    def __getattr__(self, name):
        self._deny("operation is outside the profiling read-only interface")


class _Body(_ReadOnlyProxy):
    def __init__(self, body, metrics, stats_lock):
        self._body, self._metrics, self._closed = body, metrics, False
        self._stats_lock = stats_lock
        with stats_lock:
            metrics["body"]["opened"] += 1

    def read(self, *args, **kwargs):
        stats = self._metrics["body"]
        with self._stats_lock:
            stats["read_calls"] += 1
        started = time.perf_counter()
        try:
            data = self._body.read(*args, **kwargs)
        except BaseException:
            with self._stats_lock:
                stats["read_failures"] += 1
            raise
        else:
            if isinstance(data, (bytes, bytearray, memoryview)):
                with self._stats_lock:
                    stats["bytes_returned"] += data.nbytes if isinstance(data, memoryview) else len(data)
            return data
        finally:
            elapsed = time.perf_counter() - started
            with self._stats_lock:
                stats["read_wall_seconds"] += elapsed

    def close(self, *args, **kwargs):
        stats = self._metrics["body"]
        with self._stats_lock:
            stats["close_calls"] += 1
        started = time.perf_counter()
        try:
            result = self._body.close(*args, **kwargs)
        except BaseException:
            with self._stats_lock:
                stats["close_failures"] += 1
            raise
        else:
            with self._stats_lock:
                if not self._closed:
                    stats["closed"] += 1
                    self._closed = True
            return result
        finally:
            elapsed = time.perf_counter() - started
            with self._stats_lock:
                stats["close_wall_seconds"] += elapsed


class _Paginator(_ReadOnlyProxy):
    def __init__(self, paginator, metrics, stats_lock):
        self._paginator, self._metrics, self._stats_lock = paginator, metrics, stats_lock

    def paginate(self, *args, **kwargs):
        stats = self._metrics["s3"]["list_object_versions"]
        with self._stats_lock:
            stats["paginations"] += 1
        started = time.perf_counter()
        try:
            pages = iter(self._paginator.paginate(*args, **kwargs))
        except BaseException as error:
            with self._stats_lock:
                stats["setup_failures"] += 1
                _error_retries(stats, error)
            raise
        finally:
            elapsed = time.perf_counter() - started
            with self._stats_lock:
                stats["setup_wall_seconds"] += elapsed
        while True:
            with self._stats_lock:
                stats["iterator_advances"] += 1
            started = time.perf_counter()
            try:
                page = next(pages)
            except StopIteration:
                with self._stats_lock:
                    stats["exhaustions"] += 1
                return
            except BaseException as error:
                with self._stats_lock:
                    stats["failed_advances"] += 1
                    _error_retries(stats, error)
                raise
            finally:
                elapsed = time.perf_counter() - started
                with self._stats_lock:
                    stats["wall_seconds"] += elapsed
            with self._stats_lock:
                stats["pages"] += 1
                _record_retries(stats, page)
                _record_page_rows(stats, page)
            yield page


class _S3(_ReadOnlyProxy):
    def __init__(self, client, metrics, stats_lock):
        self._client, self._metrics, self._stats_lock = client, metrics, stats_lock

    def get_paginator(self, operation_name):
        if operation_name != "list_object_versions":
            self._deny("only list_object_versions pagination is permitted")
        stats = self._metrics["s3"]["list_object_versions"]
        with self._stats_lock:
            stats["paginator_creations"] += 1
        started = time.perf_counter()
        try:
            paginator = self._client.get_paginator(operation_name)
        except BaseException as error:
            with self._stats_lock:
                stats["setup_failures"] += 1
                _error_retries(stats, error)
            raise
        finally:
            elapsed = time.perf_counter() - started
            with self._stats_lock:
                stats["setup_wall_seconds"] += elapsed
        return _Paginator(paginator, self._metrics, self._stats_lock)

    def list_object_versions(self, *args, **kwargs):
        return _call(self._metrics["s3"]["list_object_versions_direct"], self._client.list_object_versions,
                     args, kwargs, self._stats_lock, listing=True)

    def head_object(self, *args, **kwargs):
        return _call(self._metrics["s3"]["head_object"], self._client.head_object, args, kwargs, self._stats_lock)

    def get_object(self, *args, **kwargs):
        response = _call(self._metrics["s3"]["get_object"], self._client.get_object, args, kwargs, self._stats_lock)
        if isinstance(response, dict) and "Body" in response:
            response = dict(response)
            response["Body"] = _Body(response["Body"], self._metrics, self._stats_lock)
        return response


def _wrap_function(original, stats, stats_lock):
    @functools.wraps(original)
    def measured(*args, **kwargs):
        with stats_lock:
            stats["calls"] += 1
        wall, cpu = time.perf_counter(), time.process_time()
        try:
            return original(*args, **kwargs)
        except BaseException:
            with stats_lock:
                stats["failed_calls"] += 1
            raise
        finally:
            elapsed, process_cpu = time.perf_counter() - wall, time.process_time() - cpu
            with stats_lock:
                stats["wall_seconds"] += elapsed
                stats["cpu_seconds"] += process_cpu
    return measured


def profile_verify_generation(verifier, s3, ledger, previous_checkpoint, go_report,
                              metadata_bytes, created_sst_hashes, mode,
                              previous_checkpoint_sha256, *, metrics=None,
                              enumeration_workers=None, enumeration_stop=None,
                              enumeration_metrics=None):
    """Call the original verifier once; return its unmodified result and metrics.

    A nonempty metrics dictionary or overlapping profiler invocation is refused.
    CPU is process CPU, so unrelated threads would also contribute. The caller
    must not call or modify this verifier module concurrently. An exception is
    not wrapped, logged, or retried; a supplied metrics dict retains partial data.
    Omitted enumeration controls preserve the historical verifier call signature.
    Explicit workers=1 or 4 forwards only the three named candidate controls;
    enumeration_metrics is a separate empty output dictionary. The candidate
    verifier owns worker creation, bounds, cancellation checks, and joining.
    """
    if not isinstance(verifier, types.ModuleType) or not callable(getattr(verifier, "verify_generation", None)):
        raise ProfileRefusal("a pinned verifier module with verify_generation is required")
    if metrics is None:
        metrics = {}
    if type(metrics) is not dict or metrics:
        raise ProfileRefusal("metrics output must be an empty dictionary")
    candidate = {}
    if enumeration_workers is None:
        if enumeration_stop is not None or enumeration_metrics is not None:
            raise ProfileRefusal("enumeration controls require explicit worker selection")
    else:
        if type(enumeration_workers) is not int or enumeration_workers not in (1, 4):
            raise ProfileRefusal("candidate enumeration requires one or four workers")
        if enumeration_stop is not None and not callable(getattr(enumeration_stop, "is_set", None)):
            raise ProfileRefusal("enumeration cancellation token must expose is_set")
        if enumeration_metrics is not None and (
            type(enumeration_metrics) is not dict or enumeration_metrics or enumeration_metrics is metrics
        ):
            raise ProfileRefusal("enumeration metrics must be a distinct empty dictionary")
        candidate = {"enumeration_workers": enumeration_workers, "enumeration_stop": enumeration_stop,
                     "enumeration_metrics": enumeration_metrics}
    if not _PROFILE_LOCK.acquire(blocking=False):
        raise ProfileRefusal("a verification profile is already active")
    originals, stats_lock = {}, threading.Lock()
    wall, cpu = time.perf_counter(), time.process_time()
    try:
        for name in FUNCTIONS:
            original = getattr(verifier, name, None)
            if not callable(original):
                raise ProfileRefusal("verifier profiling function is unavailable")
            originals[name] = original
        metrics.update({
            "schema": 1, "scope": "read-only-full-clone-verification-profile",
            "verifier_returned": False, "wall_seconds": 0.0, "cpu_seconds": 0.0,
            "timing_semantics": "function wall/process CPU timings are inclusive, nested, and non-additive",
            "api_timing_semantics": "logical calls include SDK retries; GET wall excludes Body reads; listing wall measures iterator advances including exhaustion",
            "direct_listing_semantics": "direct listing counters measure low-level calls and all returned rows, including range lookahead; concurrent call times overlap",
            "retry_semantics": "only SDK-reported RetryAttempts; missing metadata is not evidence of zero retries",
            "failure_semantics": "failed API calls include expected absence probes; original exceptions are propagated",
            "denied_operations": 0,
            "functions": {name: _call_stats(cpu=True) for name in FUNCTIONS},
            "s3": {
                "list_object_versions": dict(_retry_stats(), paginator_creations=0, paginations=0,
                    setup_failures=0, setup_wall_seconds=0.0, iterator_advances=0, failed_advances=0,
                    exhaustions=0, pages=0, version_rows=0, latest_version_rows=0,
                    delete_marker_rows=0, latest_delete_marker_rows=0, wall_seconds=0.0),
                "list_object_versions_direct": dict(_call_stats(), **_retry_stats(),
                    pages=0, version_rows=0, latest_version_rows=0, delete_marker_rows=0,
                    latest_delete_marker_rows=0, in_flight=0, max_in_flight=0),
                "head_object": dict(_call_stats(), **_retry_stats()),
                "get_object": dict(_call_stats(), **_retry_stats()),
            },
            "body": {"opened": 0, "closed": 0, "read_calls": 0, "read_failures": 0,
                     "bytes_returned": 0, "read_wall_seconds": 0.0,
                     "close_calls": 0, "close_failures": 0, "close_wall_seconds": 0.0},
        })
        for name, original in originals.items():
            setattr(verifier, name, _wrap_function(original, metrics["functions"][name], stats_lock))
        result = verifier.verify_generation(
            s3=_S3(s3, metrics, stats_lock), ledger=ledger, previous_checkpoint=previous_checkpoint,
            go_report=go_report, metadata_bytes=metadata_bytes, created_sst_hashes=created_sst_hashes,
            mode=mode, previous_checkpoint_sha256=previous_checkpoint_sha256, **candidate)
        metrics["verifier_returned"] = True
        return result, metrics
    finally:
        for name, original in originals.items():
            setattr(verifier, name, original)
        if metrics:
            metrics["wall_seconds"] = time.perf_counter() - wall
            metrics["cpu_seconds"] = time.process_time() - cpu
        _PROFILE_LOCK.release()
