# Exhaustive version-list ranges for the Rhea read-only probe — 5 November 2026

## Purpose and scope

This design partitions a complete `ListObjectVersions` walk into at most four
concurrent key ranges. It preserves every version and delete marker under the
fixed disposable clone's `rhea/` prefix, including unexpected keys and nonlatest
history. The immutable ledger chooses balanced boundaries; it does **not** limit
which keys belong in the result.

The preceding [verification profile][profile] identified enumeration as the
largest measured part of one final verification pass. This document establishes
the implemented enumeration contract and its proof obligations. It does not claim a
measured speedup, a new checkpoint, or deployment of an optimized verifier.
Generation 9, five completed rewrites, and the five-rewrite ceiling remain fixed.
The installed controller, verifier, source pins, and database remain unchanged.

The experiment must compare its candidate with independent serial SDK paginator
walks before and after it. Only a completely equal result may be replayed through
the unchanged final verifier. Real GET and HEAD operations retain the existing
scoped client and verification rules.

## Documented API assumptions

| Property | Primary source and consequence |
| --- | --- |
| Version listing is ordered by key; each key's data versions and delete markers form its history. A key-only marker resumes after that key's last version. A key plus version marker resumes within the history. | [AWS `ListVersionsRequest`][aws-marker]. The initial lower bound can exclude one complete key without splitting its history. |
| Keys are compared by their UTF-8 byte sequences. | [AWS object-key ordering][aws-keys]. Compare the decoded string's strict UTF-8 encoding; do not use locale order, case folding, Unicode normalization, numeric SST order, or URL-encoded text. |
| A response may contain fewer than the requested maximum. Continuation uses the returned next-key and next-version markers. | [AWS REST API][aws-api]. Page length is not an exhaustion signal, and a subsequent request must not drop the version marker. |
| One key's history can span several pages. | [AWS version-list examples][aws-pages]. Seeing the upper-bound key does not complete a range. |
| A delimiter groups keys into common prefixes instead of returning every individual record. | [AWS REST API][aws-api]. The exhaustive probe must omit `Delimiter`. |
| Wasabi describes its API as compatible with AWS S3, with its API reference documenting variations and adopting the AWS API documentation. | [Wasabi API reference][wasabi-api]. AWS semantics are the compatibility basis; live serial equality still checks the actual endpoint's result. |

The REST descriptions of the next markers use wording about a not-yet-returned
position, while the SDK request documentation describes resuming after a marker.
The implementation must therefore forward the service's returned marker pair
without constructing it from a row. It must not assume the pair appears in the
current page, or require the next key to equal that page's maximum key.
[REST marker fields][aws-api] [SDK request semantics][aws-marker]

### SDK decoding is part of the contract

Botocore's `set_list_objects_encoding_type_url` adds `EncodingType=url` when the
caller omits it, and records that it did so. Its matching response handler then
decodes `KeyMarker`, `NextKeyMarker`, `Prefix`, `Delimiter`, and the key fields
inside `Versions`, `DeleteMarkers`, and `CommonPrefixes`. The `EncodingType`
label remains present. Neither version-marker field is URL-decoded by that
handler. If a caller supplies `EncodingType` explicitly, the automatic decoding
branch is not enabled. [AWS-maintained botocore handlers][botocore-handlers]

Accordingly, this probe omits `EncodingType` and uses the SDK-delivered decoded
keys without another unquote operation. A name containing literal `%2F` must
remain distinct from a name containing `/`; `+` must remain distinct from a
space. Version IDs stay opaque. The literal string `"null"` is a valid version
ID and must not be treated as Python `None` or a missing marker.
[AWS null-version behavior][aws-pages]

The reviewed runtime has **boto3 1.34.46 and botocore 1.34.46**. Its installed
`handlers.py` matches the official versioned source at SHA-256
`3f2d8de7f1f780377f5d10998146e0587bac68439b11b78cbcad384900eb54e2`.
The runner checks and records both versions and this exact file hash before
listing. The source's request and response event registrations bind these
handlers specifically to `ListObjectVersions`. [Pinned botocore source][botocore-handlers]

## Complete, disjoint partition

Let `K` be the set of all keys matching `rhea/`, ordered by UTF-8 bytes. Choose
strictly increasing boundaries `b1 < b2 < ... < bn`, with `n <= 3`. The ranges are

```
(-infinity, b1], (b1, b2], ..., (bn, +infinity).
```

The infinities are mathematical bounds, not names sent to S3. If there are no
boundaries, there is one unbounded range. Boundaries are complete object keys,
not prefixes, directory names, or numeric file-number comparisons.

For any key `k`, either it is at or below the first boundary, lies between one
unique adjacent pair, or lies above the last boundary. Therefore exactly one
range contains `k`. Every version and delete marker of `k` has that same range.
The first range includes keys before the smallest known ledger entry; the last
includes keys after the largest. An unexpected metadata object, a Unicode name,
or a previously unknown SST cannot fall between the ranges.

A boundary need not be present for this mathematical partition to hold. An
absent boundary relies on the provider treating its key-only marker as a sorted
seek position. The reviewed AWS text describes that position but does not give a
separate explicit absent-key guarantee. The fixture must exercise this case, and
the independent serial comparison must refuse any provider divergence. The live
experiment chooses boundaries from immutable ledger keys whose retained history
is also checked by the serial walk.

## One worker's algorithm

1. For the first range, omit both request markers. In particular, do not use
   `KeyMarker="rhea/"`, which could skip an object whose entire key is `rhea/`.
   For every other range, start with `KeyMarker=lower` and omit
   `VersionIdMarker`. Always request the exact bucket and prefix, without a
   delimiter or a client-side maximum-item truncation.
2. Read a complete response. Validate and process **both** `Versions` and
   `DeleteMarkers`. They are separate arrays, so concatenating them does not
   reconstruct the service's combined order. Retain every row satisfying
   `lower < key <= upper`, with absent bounds treated as unbounded.
3. A returned key above the upper bound proves that the ordered walk has passed
   all of that range's keys. Finish processing both arrays before completing the
   range. Such lookahead rows consume the probe's work budget but are not part of
   this range's result.
4. Otherwise, `IsTruncated=False` completes the range. Seeing `key == upper`, a
   short page, or an empty page does not independently establish completion.
5. If more results remain, pass the exact returned `NextKeyMarker` and
   `NextVersionIdMarker` to the next request. Continue even when the key marker
   stays the same: the version marker can advance through a long history.
   Never sort version IDs to infer chronology or pagination progress.

Each finite worker starts immediately after its excluded lower key and follows
the service's complete continuation chain. It stops only after passing its
included upper key or exhausting the prefix. Consequently it retains every
record in its interval. The partition then makes the union exhaustive and
disjoint. This conclusion depends on the documented ordering and continuation
contract; monotonicity checks alone cannot detect a provider silently omitting a
record. The independent serial walks address that risk for the frozen dataset.

### Boundary histories and array separation

If the upper key has thousands of versions, the worker continues through all its
pages, including pages containing only that key. A delete marker can be the
latest record while older data versions remain in another array. Conversely,
the page can contain a data version above the upper bound and a delete marker
within it. Stopping at the first out-of-range row in the first array would lose
the latter record. Both arrays must be consumed before the completion decision.

Adjacent workers can observe the same lookahead record in network responses.
That is expected overhead. It is not duplicate inclusion: only the worker whose
interval contains its key retains it. Duplicate detection must distinguish
observed lookahead from accepted output.

## Refusal rules and work bounds

The scanner must fail the probe rather than return a partial successful snapshot
when its supported contract is violated. Required checks include:

- Strictly increasing, valid UTF-8 boundaries within the fixed prefix; no more
  than three boundaries or four concurrent workers.
- Parsed response types, explicit Boolean truncation state, matching key prefix,
  and no unexpected grouped `CommonPrefixes`. Invalid XML or SDK errors are
  failures even if the HTTP status is 200. [AWS response warning][aws-api]
- No row at or below a worker's excluded lower key; no backward movement between
  pages. A repeated key is allowed while its versions continue. Each returned
  array must preserve its key ordering, without assuming an ordering between the
  two arrays.
- No repeated accepted `(Key, VersionId)` identity, even if the repeated row is
  byte-for-byte equivalent. An identity appearing as both a data version and a
  delete marker is also invalid. Preserve all fields of each accepted record.
- Valid continuation tokens and no repeated token pair or cycle. This bounded
  probe may refuse missing or empty next-version markers on a truncated page as
  unsupported; it must not guess a marker or silently change to key-only
  continuation. The string `"null"` remains valid.
- An empty truncated response is outside the implemented probe's supported
  contract and causes refusal. It is never interpreted as exhaustion.
- Limits of **512 response pages** and **500,000 returned rows per scan**, counting
  both arrays and lookahead globally across workers. Request slots are reserved
  before calls; the row limit is checked after each whole response arrives. An
  over-budget response or already in-flight sibling call can therefore have
  received rows before refusal. No over-budget snapshot is accepted. The request
  bound and `MaxKeys=1000` separately bound requested records, while SDK retries
  are additional attempts. Cap exhaustion is never evidence of completion.

These are conservative probe preconditions, not a claim that every S3-compatible
provider must emit every optional field in the same way. A rejected provider
response leaves the installed serial verifier as the operational implementation.

The caller supplies a scoped low-level client constructed before the workers
start. It must not mutate SDK handlers or close the client while listing work is
outstanding. Cancellation stops additional work, drains workers, and prevents
partial snapshots from reaching the verifier. A main-thread alarm is not a hard
deadline for worker threads; a separately supervised read-only process supplies
the outer timeout. The existing reader-active health checks and exclusive lock
remain required, without admitting a database writer.

## Independent equality and verifier replay

The three walks are serial-before, candidate parallel enumeration, and
serial-after. The two serial walks use the original SDK paginator, not the
candidate's manual range implementation. Compare all complete row dictionaries,
including record kind, key, version ID, latest flag, size, ETag, timestamps,
ownership, and any other returned fields. Compare unordered record collections;
the two response arrays and concurrent worker completion do not define one
portable aggregate order. Reject duplicates before comparing the collections.

Counts or a latest-only map cannot establish this equality. Equal digests are
useful receipts only when computed from an unambiguous canonical representation
of those complete records. The comparison includes nonlatest versions and
delete markers; filtering to ledger keys or SST-looking names would invalidate
the exhaustive claim. The before/after serial comparison also detects observed
change during the experiment. It does not create an atomic S3 snapshot or prove
the absence of every transient external change.

After all listing workers have finished, a snapshot adapter may supply the
candidate's complete records to the **unchanged** verifier. Its GET and HEAD
calls still reach the same scoped client. The semantic comparison remains the
one established in the [completed replay][profile]: remove only the controlled
`verified_unix` timestamp from the actual result; remove `generation`, `reopen`,
`reopen_scope`, and `verified_unix` from the reference certificate; set the
reference's `pebble_reopen_verified` to `False`; require that flag to be exactly
`False` in the actual result; and require all remaining output to match exactly.
The actual timestamp must also be a finite, non-Boolean number within the replay interval.
Its canonical expected projection is
`0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57`.

Neither the equality check nor this replay opens Pebble, publishes metadata,
increments a generation, or authorizes an additional rewrite. Any mismatch,
provider incompatibility, timeout, or changed health/state binding ends the
experiment without installation.

## Focused validation cases

The reviewed implementation is [the importable scanner][scanner], SHA-256
`512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359`.
Its [focused test file][scanner-tests] has SHA-256
`0a6aa7e2820ebdfe7f317df0280b69b98d845358d4fd317cb9db87ff69504d5d`.
Independent source review found no record-loss or worker-drain blocker, and all
**17 focused tests passed**. The review checks the following obligations;
synthetic fixtures validate implementation behavior, not remote-provider
compliance.

| Case | Required result |
| --- | --- |
| Empty prefix; key exactly `rhea/`; keys before, between, and after ledger boundaries | Complete coverage without a synthetic starting marker or a known-name filter. |
| Upper-bound key spans many pages, with data versions and delete markers interleaved | Every version retained; stop only after a greater key or exhaustion. |
| A greater key appears in one array while an in-range key appears in the other | Both arrays processed before stopping. |
| Absent boundary; literal percent sequences; plus signs; composed and decomposed Unicode | Strict decoded UTF-8 comparisons with no normalization or double decoding. |
| Literal `"null"` version ID; opaque version IDs whose lexical order differs from chronology | Exact token forwarding, with no version-ID ordering assumption. |
| Duplicate identities, backward keys, marker cycles, malformed pages, unsupported continuation | Explicit failure and no partial snapshot. |
| A worker fails or a global page/row budget is reached | Other work is cancelled/drained; no verifier replay follows. |
| Unequal serial snapshots or any candidate record mutation | Equality fails even when total counts and latest-file counts match. |

The focused test command is:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p test_enumerate_rhea_versions.py -v
```

The [separate fixed runner][runner] owns the independent SDK walks, full-record
equality, exact generation-9 inputs, health and source bindings, and unchanged
verifier replay. Those checks are additional to the scanner's local fixtures.
The scanner itself creates no client, obtains no credentials, and invokes only
`list_object_versions` on the supplied client.

Live measurements belong in a separate results report. They should distinguish
wall time, aggregate request time, CPU, page and row counts, lookahead overhead,
SDK retries, per-range load balance, and peak memory. A single ordered
serial/parallel/serial sequence can show its observed timing ratio; it cannot
isolate network latency, establish cold-cache throughput, or predict the complete
duration of a future writer/checkpoint cycle.

[profile]: rhea-full-clone-verification-profile-20261105.md
[scanner]: ../scripts/enumerate_rhea_versions.py
[scanner-tests]: ../tests/test_enumerate_rhea_versions.py
[runner]: ../scripts/run_rhea_version_enumeration_profile.py
[aws-marker]: https://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/com/amazonaws/services/s3/model/ListVersionsRequest.html
[aws-keys]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html
[aws-api]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html
[aws-pages]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/list-obj-version-enabled-bucket.html
[wasabi-api]: https://docs.wasabi.com/apidocs/wasabi-api
[botocore-handlers]: https://github.com/boto/botocore/blob/1.34.46/botocore/handlers.py
