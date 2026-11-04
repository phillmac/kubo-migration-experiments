#!/usr/bin/env python3
"""Profile an injected, pinned full-clone verifier without changing its proof.

This is an importable measurement utility, not a controller or CLI. The caller
owns source pins, exclusive use of the verifier module, credentials, lifecycle
locks, snapshot guards, and client closure. There is no filesystem or SDK setup.
Only the verifier module's named functions are temporarily wrapped; an SDK is
never monkeypatched. Function timings are inclusive and must not be summed.

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
    except Exception:
        pass


def _call(stats, operation, *args, **kwargs):
    stats["calls"] += 1
    started = time.perf_counter()
    try:
        response = operation(*args, **kwargs)
    except BaseException as error:
        stats["failed_calls"] += 1
        _error_retries(stats, error)
        raise
    else:
        _record_retries(stats, response)
        return response
    finally:
        stats["wall_seconds"] += time.perf_counter() - started


class _ReadOnlyProxy:
    def __getattr__(self, name):
        self._metrics["denied_operations"] += 1
        raise ProfileRefusal("operation is outside the profiling read-only interface")


class _Body(_ReadOnlyProxy):
    def __init__(self, body, metrics):
        self._body, self._metrics, self._closed = body, metrics, False
        metrics["body"]["opened"] += 1

    def read(self, *args, **kwargs):
        stats = self._metrics["body"]
        stats["read_calls"] += 1
        started = time.perf_counter()
        try:
            data = self._body.read(*args, **kwargs)
        except BaseException:
            stats["read_failures"] += 1
            raise
        else:
            if isinstance(data, (bytes, bytearray, memoryview)):
                stats["bytes_returned"] += data.nbytes if isinstance(data, memoryview) else len(data)
            return data
        finally:
            stats["read_wall_seconds"] += time.perf_counter() - started

    def close(self, *args, **kwargs):
        stats = self._metrics["body"]
        stats["close_calls"] += 1
        started = time.perf_counter()
        try:
            result = self._body.close(*args, **kwargs)
        except BaseException:
            stats["close_failures"] += 1
            raise
        else:
            if not self._closed:
                stats["closed"] += 1
                self._closed = True
            return result
        finally:
            stats["close_wall_seconds"] += time.perf_counter() - started


class _Paginator(_ReadOnlyProxy):
    def __init__(self, paginator, metrics):
        self._paginator, self._metrics = paginator, metrics

    def paginate(self, *args, **kwargs):
        stats = self._metrics["s3"]["list_object_versions"]
        stats["paginations"] += 1
        started = time.perf_counter()
        try:
            pages = iter(self._paginator.paginate(*args, **kwargs))
        except BaseException as error:
            stats["setup_failures"] += 1
            _error_retries(stats, error)
            raise
        finally:
            stats["setup_wall_seconds"] += time.perf_counter() - started
        while True:
            stats["iterator_advances"] += 1
            started = time.perf_counter()
            try:
                page = next(pages)
            except StopIteration:
                stats["exhaustions"] += 1
                return
            except BaseException as error:
                stats["failed_advances"] += 1
                _error_retries(stats, error)
                raise
            finally:
                stats["wall_seconds"] += time.perf_counter() - started
            stats["pages"] += 1
            _record_retries(stats, page)
            if isinstance(page, dict):
                for field, counter in (("Versions", "version_rows"), ("DeleteMarkers", "delete_marker_rows")):
                    rows = page.get(field)
                    if isinstance(rows, (list, tuple)):
                        stats[counter] += len(rows)
                        stats["latest_" + counter] += sum(
                            isinstance(row, dict) and row.get("IsLatest") is True for row in rows)
            yield page


class _S3(_ReadOnlyProxy):
    def __init__(self, client, metrics):
        self._client, self._metrics = client, metrics

    def get_paginator(self, operation_name):
        if operation_name != "list_object_versions":
            self._metrics["denied_operations"] += 1
            raise ProfileRefusal("only list_object_versions pagination is permitted")
        stats = self._metrics["s3"]["list_object_versions"]
        stats["paginator_creations"] += 1
        started = time.perf_counter()
        try:
            paginator = self._client.get_paginator(operation_name)
        except BaseException as error:
            stats["setup_failures"] += 1
            _error_retries(stats, error)
            raise
        finally:
            stats["setup_wall_seconds"] += time.perf_counter() - started
        return _Paginator(paginator, self._metrics)

    def head_object(self, *args, **kwargs):
        return _call(self._metrics["s3"]["head_object"], self._client.head_object, *args, **kwargs)

    def get_object(self, *args, **kwargs):
        response = _call(self._metrics["s3"]["get_object"], self._client.get_object, *args, **kwargs)
        if isinstance(response, dict) and "Body" in response:
            response = dict(response)
            response["Body"] = _Body(response["Body"], self._metrics)
        return response


def _wrap_function(original, stats):
    @functools.wraps(original)
    def measured(*args, **kwargs):
        stats["calls"] += 1
        wall, cpu = time.perf_counter(), time.process_time()
        try:
            return original(*args, **kwargs)
        except BaseException:
            stats["failed_calls"] += 1
            raise
        finally:
            stats["wall_seconds"] += time.perf_counter() - wall
            stats["cpu_seconds"] += time.process_time() - cpu
    return measured


def profile_verify_generation(verifier, s3, ledger, previous_checkpoint, go_report,
                              metadata_bytes, created_sst_hashes, mode,
                              previous_checkpoint_sha256, *, metrics=None):
    """Call the original verifier once; return its unmodified result and metrics.

    A nonempty metrics dictionary or overlapping profiler invocation is refused.
    CPU is process CPU, so unrelated threads would also contribute. The caller
    must not call or modify this verifier module concurrently. An exception is
    not wrapped, logged, or retried; a supplied metrics dict retains partial data.
    """
    if not isinstance(verifier, types.ModuleType) or not callable(getattr(verifier, "verify_generation", None)):
        raise ProfileRefusal("a pinned verifier module with verify_generation is required")
    if metrics is None:
        metrics = {}
    if type(metrics) is not dict or metrics:
        raise ProfileRefusal("metrics output must be an empty dictionary")
    if not _PROFILE_LOCK.acquire(blocking=False):
        raise ProfileRefusal("a verification profile is already active")
    originals = {}
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
            "retry_semantics": "only SDK-reported RetryAttempts; missing metadata is not evidence of zero retries",
            "failure_semantics": "failed API calls include expected absence probes; original exceptions are propagated",
            "denied_operations": 0,
            "functions": {name: _call_stats(cpu=True) for name in FUNCTIONS},
            "s3": {
                "list_object_versions": dict(_retry_stats(), paginator_creations=0, paginations=0,
                    setup_failures=0, setup_wall_seconds=0.0, iterator_advances=0, failed_advances=0,
                    exhaustions=0, pages=0, version_rows=0, latest_version_rows=0,
                    delete_marker_rows=0, latest_delete_marker_rows=0, wall_seconds=0.0),
                "head_object": dict(_call_stats(), **_retry_stats()),
                "get_object": dict(_call_stats(), **_retry_stats()),
            },
            "body": {"opened": 0, "closed": 0, "read_calls": 0, "read_failures": 0,
                     "bytes_returned": 0, "read_wall_seconds": 0.0,
                     "close_calls": 0, "close_failures": 0, "close_wall_seconds": 0.0},
        })
        for name, original in originals.items():
            setattr(verifier, name, _wrap_function(original, metrics["functions"][name]))
        result = verifier.verify_generation(
            s3=_S3(s3, metrics), ledger=ledger, previous_checkpoint=previous_checkpoint,
            go_report=go_report, metadata_bytes=metadata_bytes, created_sst_hashes=created_sst_hashes,
            mode=mode, previous_checkpoint_sha256=previous_checkpoint_sha256)
        metrics["verifier_returned"] = True
        return result, metrics
    finally:
        for name, original in originals.items():
            setattr(verifier, name, original)
        if metrics:
            metrics["wall_seconds"] = time.perf_counter() - wall
            metrics["cpu_seconds"] = time.process_time() - cpu
        _PROFILE_LOCK.release()
