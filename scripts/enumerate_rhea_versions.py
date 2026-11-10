#!/usr/bin/env python3
"""Capture a bounded, exhaustive S3 version listing using disjoint key ranges.

This importable utility performs only list_object_versions calls on a supplied
low-level SDK client. The caller owns client creation, credentials, identity
checks, consistency checks against independent serial listings, and closure.
It is not a production verifier or a controller.

Ranges are (-infinity, b1], (b1, b2], ..., (bn, infinity). An initial KeyMarker
alone skips every version of the lower key. Subsequent requests forward the
exact returned key/version marker pair. Both response arrays are processed in
full, including a page that crosses the upper bound. Keys use UTF-8 byte order;
version IDs are opaque, including the literal string "null".

The supplied client must return SDK-decoded key fields. Requests deliberately
omit EncodingType: botocore automatically requests URL encoding and decodes key
fields once, while leaving EncodingType="url" in the response. This module never
URL-decodes keys or version IDs itself. Missing/empty continuation version IDs
on truncated pages are outside this bounded, no-delimiter probe's scope.

The global page cap is reserved under a lock before requests. The row cap counts
all received rows, including lookahead outside a range, before retaining them.
Already running SDK calls cannot be interrupted by a cancellation flag. Failure
stops new requests and drains all workers before raising; a caller that needs a
hard deadline must supervise the whole process. No partial snapshot is returned.

The snapshot contains complete, deep-copied raw row dictionaries keyed by
(Key, VersionId), separately for Versions and DeleteMarkers. Metrics contain
bounded counters, timings, range indices, and fixed labels only. API timings
include SDK processing; overlapping range/API timings must not be summed to
infer elapsed wall time. This module does not log exception text or any keys.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import threading
import time


MAX_WORKERS = 4
MAX_RANGES = 4
PAGE_SIZE = 1000
_PAGE_FIELDS = frozenset({
    "IsTruncated", "KeyMarker", "VersionIdMarker", "NextKeyMarker",
    "NextVersionIdMarker", "Versions", "DeleteMarkers", "Name", "Prefix",
    "Delimiter", "MaxKeys", "CommonPrefixes", "EncodingType", "RequestCharged",
    "ResponseMetadata",
})
_SUM_FIELDS = (
    "requests", "pages", "version_rows", "delete_marker_rows", "retained_versions",
    "retained_delete_markers", "discarded_rows", "responses_with_retry_metadata",
    "reported_retry_attempts", "api_wall_seconds",
)


class ScanRefusal(RuntimeError):
    """The request or response exceeds the bounded listing contract."""


class ScanCancelled(ScanRefusal):
    """Cancellation was observed; no complete snapshot is available."""


def _key_bytes(value, *, allow_empty=False):
    if type(value) is not str or (not value and not allow_empty):
        raise ScanRefusal("key field is not a supported string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ScanRefusal("key field is not valid UTF-8") from None
    if len(encoded) > 1024:
        raise ScanRefusal("key field exceeds the S3 key length limit")
    return encoded


def _version(value):
    if type(value) is not str or not value:
        raise ScanRefusal("version field is not a nonempty opaque string")
    return value


def _positive_int(value, label, maximum=None):
    if type(value) is not int or value <= 0 or (maximum is not None and value > maximum):
        raise ScanRefusal(label)


def _range_stats(index):
    result = {name: 0 for name in _SUM_FIELDS}
    result.update(index=index, api_wall_seconds=0.0, wall_seconds=0.0,
                  max_reported_retry_attempts=0, termination="")
    return result


class _Shared:
    def __init__(self, max_pages, max_rows, external_stop):
        self.max_pages, self.max_rows = max_pages, max_rows
        self.external_stop = external_stop
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.requests = self.rows = 0
        self.first_error = None

    def check(self):
        if self.stop.is_set() or (self.external_stop is not None and self.external_stop.is_set()):
            raise ScanCancelled("version enumeration was cancelled")

    def reserve(self):
        with self.lock:
            self.check()
            if self.requests >= self.max_pages:
                raise ScanRefusal("global version-list request budget exhausted")
            self.requests += 1

    def account_rows(self, count):
        with self.lock:
            self.check()
            if self.rows + count > self.max_rows:
                raise ScanRefusal("global received-row budget exhausted")
            self.rows += count

    def fail(self, error):
        with self.lock:
            if self.first_error is None:
                self.first_error = error
            self.stop.set()


def _record_retries(stats, page):
    metadata = page.get("ResponseMetadata")
    attempts = metadata.get("RetryAttempts") if isinstance(metadata, dict) else None
    if type(attempts) is int and 0 <= attempts <= 2**31 - 1:
        stats["responses_with_retry_metadata"] += 1
        stats["reported_retry_attempts"] += attempts
        stats["max_reported_retry_attempts"] = max(stats["max_reported_retry_attempts"], attempts)


def _page_rows(page, bucket, prefix, cursor):
    if type(page) is not dict or not set(page).issubset(_PAGE_FIELDS):
        raise ScanRefusal("version-list response has an unsupported top-level schema")
    if type(page.get("IsTruncated")) is not bool:
        raise ScanRefusal("version-list truncation flag is missing or malformed")
    for field, expected in (("Name", bucket), ("Prefix", prefix),
                            ("KeyMarker", cursor[0] or ""),
                            ("VersionIdMarker", cursor[1] or "")):
        if field in page and (type(page[field]) is not str or page[field] != expected):
            raise ScanRefusal("version-list response does not match its request")
    if "Delimiter" in page and page["Delimiter"] != "":
        raise ScanRefusal("delimiter-based listings are unsupported")
    if "CommonPrefixes" in page and (type(page["CommonPrefixes"]) is not list or page["CommonPrefixes"]):
        raise ScanRefusal("grouped version-list records are unsupported")
    if "EncodingType" in page and page["EncodingType"] != "url":
        raise ScanRefusal("version-list encoding label is unsupported")
    if "ResponseMetadata" in page and type(page["ResponseMetadata"]) is not dict:
        raise ScanRefusal("version-list response metadata is malformed")
    maximum = page.get("MaxKeys", PAGE_SIZE)
    _positive_int(maximum, "version-list page size is malformed", PAGE_SIZE)
    arrays = (page.get("Versions", []), page.get("DeleteMarkers", []))
    if any(type(rows) is not list for rows in arrays):
        raise ScanRefusal("version-list row array is malformed")
    count = sum(map(len, arrays))
    if count > maximum or (page["IsTruncated"] and count == 0):
        raise ScanRefusal("version-list page has an unsupported row count")
    return arrays


def _scan_range(s3, bucket, prefix, lower, upper, index, shared):
    stats, snapshot = _range_stats(index), {"Versions": {}, "DeleteMarkers": {}}
    started = time.perf_counter()
    lower_bytes = None if lower is None else _key_bytes(lower)
    upper_bytes = None if upper is None else _key_bytes(upper)
    cursor = (lower, None)
    seen_cursors, seen_rows = set(), set()
    previous_max = None
    try:
        while True:
            shared.reserve()
            stats["requests"] += 1
            request = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": PAGE_SIZE}
            if cursor[0] is not None:
                request["KeyMarker"] = cursor[0]
            if cursor[1] is not None:
                request["VersionIdMarker"] = cursor[1]
            call_started = time.perf_counter()
            try:
                page = s3.list_object_versions(**request)
            finally:
                stats["api_wall_seconds"] += time.perf_counter() - call_started
            shared.check()
            arrays = _page_rows(page, bucket, prefix, cursor)
            shared.account_rows(sum(map(len, arrays)))
            stats["pages"] += 1
            _record_retries(stats, page)
            crossed_upper, page_max = False, None
            cursor_bytes = None if cursor[0] is None else _key_bytes(cursor[0])
            for field, rows, received, retained in (
                ("Versions", arrays[0], "version_rows", "retained_versions"),
                ("DeleteMarkers", arrays[1], "delete_marker_rows", "retained_delete_markers"),
            ):
                stats[received] += len(rows)
                array_previous = None
                for row in rows:
                    if type(row) is not dict:
                        raise ScanRefusal("version-list row is not a dictionary")
                    key = row.get("Key")
                    encoded = _key_bytes(key)
                    version = _version(row.get("VersionId"))
                    if not key.startswith(prefix) or type(row.get("IsLatest")) is not bool:
                        raise ScanRefusal("version-list row has an invalid scope or latest flag")
                    if field == "Versions" and (
                        type(row.get("Size")) is not int or row["Size"] < 0
                        or type(row.get("ETag")) is not str or not row["ETag"]
                    ):
                        raise ScanRefusal("version-list object size or ETag is malformed")
                    if ((array_previous is not None and encoded < array_previous)
                            or (previous_max is not None and encoded < previous_max)
                            or (cursor_bytes is not None and encoded < cursor_bytes)
                            or (lower_bytes is not None and encoded <= lower_bytes)):
                        raise ScanRefusal("version-list keys moved backward or crossed the exclusive lower bound")
                    array_previous = encoded
                    page_max = encoded if page_max is None else max(page_max, encoded)
                    identity = (key, version)
                    if identity in seen_rows:
                        raise ScanRefusal("version-list returned a duplicate key/version identity")
                    seen_rows.add(identity)
                    if upper_bytes is not None and encoded > upper_bytes:
                        crossed_upper = True
                        stats["discarded_rows"] += 1
                    else:
                        snapshot[field][identity] = copy.deepcopy(row)
                        stats[retained] += 1
            next_cursor = None
            if page["IsTruncated"]:
                next_key = page.get("NextKeyMarker")
                next_bytes = _key_bytes(next_key)
                next_version = _version(page.get("NextVersionIdMarker"))
                next_cursor = (next_key, next_version)
                if (not next_key.startswith(prefix)
                        or (cursor_bytes is not None and next_bytes < cursor_bytes)
                        or (page_max is not None and next_bytes < page_max)
                        or next_cursor == cursor or next_cursor in seen_cursors):
                    raise ScanRefusal("version-list continuation did not make valid forward progress")
                seen_cursors.add(next_cursor)
            if crossed_upper or not page["IsTruncated"]:
                stats["termination"] = "upper-crossed" if crossed_upper else "exhausted"
                return snapshot, stats
            previous_max, cursor = page_max, next_cursor
    except BaseException as error:
        shared.fail(error)
        raise
    finally:
        stats["wall_seconds"] = time.perf_counter() - started


def scan_versions(s3, *, bucket, prefix, boundaries=(), workers=1,
                  max_pages=512, max_rows=500_000, stop_event=None):
    """Return (complete raw snapshot, sanitized metrics), or raise after joining.

    Boundaries must be at most three unique, increasing, full keys within prefix.
    The optional cancellation token needs only is_set(); it is never modified.
    SDK exceptions propagate unchanged. Max pages applies to all reserved calls;
    max rows applies to all received records, including overlapping lookahead.
    There are no utility retries. Every complete key must have exactly one latest
    record across its ordinary versions and delete markers.
    """
    if type(bucket) is not str or not bucket:
        raise ScanRefusal("a bucket string is required")
    _key_bytes(prefix, allow_empty=True)
    if type(boundaries) not in (tuple, list) or len(boundaries) >= MAX_RANGES:
        raise ScanRefusal("at most three explicit key boundaries are supported")
    encoded = [_key_bytes(key) for key in boundaries]
    if any(not key.startswith(prefix) for key in boundaries) or any(
        left >= right for left, right in zip(encoded, encoded[1:])
    ):
        raise ScanRefusal("key boundaries must be unique, increasing, and within the prefix")
    _positive_int(workers, "worker count is outside the supported bound", MAX_WORKERS)
    _positive_int(max_pages, "global page budget must be a positive integer")
    _positive_int(max_rows, "global row budget must be a positive integer")
    if stop_event is not None and not callable(getattr(stop_event, "is_set", None)):
        raise ScanRefusal("cancellation token must expose is_set")
    if not callable(getattr(s3, "list_object_versions", None)):
        raise ScanRefusal("a low-level version-list client is required")
    boundaries = tuple(boundaries)
    shared = _Shared(max_pages, max_rows, stop_event)
    shared.check()
    wall, cpu = time.perf_counter(), time.process_time()
    ranges = tuple(zip((None,) + boundaries, boundaries + (None,)))
    effective_workers = min(workers, len(ranges))
    futures, results = [], []
    # Joining occurs before exceptions leave the utility and the caller can
    # close its client. Queued ranges also see the internal cancellation latch.
    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        try:
            for index, (lower, upper) in enumerate(ranges):
                futures.append(executor.submit(
                    _scan_range, s3, bucket, prefix, lower, upper, index, shared))
            for future in futures:
                results.append(future.result())
        except BaseException as error:
            shared.fail(error)
        finally:
            for future in futures:
                try:
                    future.result()
                except BaseException as error:
                    shared.fail(error)
    if shared.first_error is not None:
        raise shared.first_error
    shared.check()
    snapshot, identities, latest = {"Versions": {}, "DeleteMarkers": {}}, set(), {}
    range_metrics = []
    for part, stats in results:
        range_metrics.append(stats)
        for field in ("Versions", "DeleteMarkers"):
            for identity, row in part[field].items():
                if identity in identities:
                    raise ScanRefusal("range union contains a duplicate key/version identity")
                identities.add(identity)
                snapshot[field][identity] = row
                latest[row["Key"]] = latest.get(row["Key"], 0) + int(row["IsLatest"])
    if any(count != 1 for count in latest.values()):
        raise ScanRefusal("a complete key does not have exactly one latest record")
    shared.check()
    metrics = {name: sum(stats[name] for stats in range_metrics) for name in _SUM_FIELDS}
    metrics.update(
        schema=1, complete=True, workers=effective_workers, range_count=len(ranges),
        max_pages=max_pages, max_rows=max_rows, ranges=range_metrics,
        max_reported_retry_attempts=max(stats["max_reported_retry_attempts"] for stats in range_metrics),
        wall_seconds=time.perf_counter() - wall, cpu_seconds=time.process_time() - cpu,
        timing_scope="API includes SDK processing; concurrent timings overlap",
    )
    return snapshot, metrics
