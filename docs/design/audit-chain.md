# Audit hash chain

**Status:** implemented in the audit core arc (milestone M1); external anchoring (section 7) added in 0.1.0 before b1.
**Code:** `src/warden/audit/chain.py` (canonical form and hash), `src/warden/audit/recorder.py` (appending), `src/warden/audit/anchor.py` and `src/warden/audit/verify.py` (anchors).

This document specifies how warden makes its audit trail tamper-evident (design D13), precisely enough that a verifier can be written without reading warden's code.

## 1. Rows and links

Every row of `warden.audit_events` stores:

| Column | Meaning |
|---|---|
| `id` | Position in the chain. Drawn under the chain lock (section 3), so ids increase in commit order. Gaps are normal: a rolled-back write consumes an id. |
| `recorded_at` | Server time (`clock_timestamp()`) when the row was appended. Cannot be supplied by the caller. Retention measures age by it. |
| `occurred_at` | When the product says the event happened. Caller-supplied, so it may be backdated; chain order never follows it. |
| `actor`, `action`, `resource_type`, `resource_id`, `outcome`, `source_ip`, `details`, `key_id` | The event. `outcome` is `success` or `failure` (a database CHECK). |
| `prev_hash` | The `row_hash` of the row before it in id order, or 32 zero bytes (the genesis hash) for the first row ever written. |
| `row_hash` | SHA-256 over the row's canonical form (section 2). |

`prev_hash` is unique (a database index), so two rows can never claim the same predecessor: the chain cannot fork, even if a writer reads a stale head.

## 2. Canonical form

```
row_hash = SHA-256( "warden.audit.row.v1\n" || canonical_json(fields) )
```

`fields` is a JSON object with exactly these members:

| Member | Encoding |
|---|---|
| `id` | integer |
| `prev_hash` | lower-case hex string of the 32 bytes |
| `recorded_at`, `occurred_at` | UTC, `YYYY-MM-DDTHH:MM:SS.ffffffZ` (always six fractional digits) |
| `actor`, `action`, `resource_type`, `resource_id`, `outcome`, `key_id` | string, or `null` when absent |
| `source_ip` | the address in fully expanded form (IPv4 dotted quad; IPv6 eight groups of four lower-case hex digits), or `null` |
| `details` | the stored JSON object |

`canonical_json` is:

- UTF-8, with no byte-order mark;
- object members sorted by key, comparing keys by Unicode code point;
- no whitespace outside strings, `,` between items and `:` between key and value;
- strings escaped as JSON requires and otherwise left as they are (non-ASCII characters are not escaped);
- `true`, `false` and `null` as literals;
- **one text per number.** Postgres stores jsonb numbers as `numeric`, so `1e20` comes back as an integer and `1.0` may come back as `1`. A number is therefore written as its exact decimal value in plain notation, with no exponent, no trailing fractional zeros, no trailing decimal point, and `0` for any zero (including negative zero). For example, `1e20` is written `100000000000000000000`, `1.0` is written `1`, and `1.5e-7` is written `0.00000015`.

Details containing a non-finite number or a NUL character are refused before anything is written, because jsonb cannot store them.

## 3. Appending

The recorder appends a row as follows:

1. If warden begins the transaction, it sets `READ COMMITTED`.
2. It takes the **chain lock**: `pg_advisory_xact_lock(0x7761_7264_656E_0003)`. This is transaction-scoped and is released only when the transaction ends.
3. In a **separate statement**, so that under READ COMMITTED the snapshot postdates the lock, it draws the next id (`nextval`), reads `clock_timestamp()` and reads the current head's `row_hash`.
4. It computes `row_hash` and inserts the row with its explicit id.
5. It issues `pg_notify('warden_audit', <id>)` in the same transaction.

Because the lock is taken before the id is drawn and held to the end of the transaction, **a row with a higher id never commits before a row with a lower id**. The syslog forwarder relies on this when it reads committed rows by id.

The cost is that audit writes are serialised. A record written inside a caller's transaction (`record(event, conn=...)`) holds the lock until the caller commits or rolls back, and every other audit write waits behind it. Keep such transactions short.

A REPEATABLE READ or SERIALIZABLE caller transaction whose snapshot predates the head would read a stale head. The unique `prev_hash` index makes the insert fail instead of forking, and the recorder raises `AuditChainConflict`, which the caller retries like any serialisation failure.

## 4. Details cap

Details whose canonical form exceeds `audit.details_max_bytes` (default 8192) are replaced whole by the declared marker:

```json
{"warden.truncated": {"original_bytes": 10012}}
```

The marker records the original size and none of the content, so a stored value is never a fragment. The key `warden.truncated` is reserved, and a product may not supply it. Sinks are offered the stored form.

## 5. What the chain does and does not show

Verification (`warden audit verify`) recomputes every `row_hash` and checks every link. It names the first broken row when any column of a row is altered, a row is deleted or rows are reordered.

A hash chain alone cannot stop someone who can write to the table from rewriting the chain from some point onwards, or from deleting rows at its tail. Retention checkpoints (section 6) cannot be forged without warden's signing key, but such a person could still delete a checkpoint together with every row before it, and rewrite what remains as a fresh chain from genesis. Detecting that, and tail deletion, needs the chain head anchored outside the database: signed anchors (section 7), held in a SIEM, checked with `warden audit verify --anchors FILE`.

## 6. Retention checkpoints

**Code:** `src/warden/audit/retention.py`, `src/warden/audit/checkpoint.py`.

A retention purge (`warden audit purge`) deletes the oldest part of the chain. It always deletes a **prefix by id**: rows `first_purged_id` to `through_id`, where every row in the prefix has a `recorded_at` older than the cutoff (now minus `audit.retention_days`). A row younger than the cutoff is never deleted, even if an older row follows it after a clock step. The retention period may not be shorter than the enforced minimum, `warden.config.MIN_RETENTION_DAYS` (365 days).

Before deleting anything, the purge verifies the prefix. If the prefix is broken, the purge is refused and the refusal is recorded (action `warden.audit.purge`, outcome `failure`, details `{"reason": "chain_broken", "row_id": N}`). A purge can therefore never launder tampering by deleting the evidence.

The purge then appends, in one transaction, a **checkpoint row** and deletes the prefix. The checkpoint row has action `warden.audit.purge` and outcome `success`, and is the purge's own audit record. Its details are:

```json
{"checkpoint": {
  "version": 1,
  "first_purged_id": 1, "through_id": 4000, "purged_rows": 3990,
  "through_hash": "<hex row_hash of row through_id>",
  "cutoff": "<ISO 8601 UTC>", "retention_days": 365,
  "key_id": "<signing key id>",
  "signature": "<base64url Ed25519 signature>"
}}
```

The signature covers

```
"warden.audit.checkpoint.v1\n" || canonical_json(checkpoint without "signature")
```

and is made with warden's active Ed25519 key (design D14). Checkpoint details are never truncated.

### Verifying across a checkpoint

After a purge, the first surviving row's `prev_hash` is the `row_hash` of a row that no longer exists. Verification accepts it only if some checkpoint row satisfies all of the following:

- its `through_hash` equals that `prev_hash`;
- its `through_id` is lower than the first surviving row's id;
- its signature verifies with `verify_historical`.

`verify_historical` accepts a key retired by routine rotation, but never a revoked one. Every checkpoint row met during verification is checked the same way, whether or not it anchors the chain. The report distinguishes:

- a malformed checkpoint;
- a bad signature, from a forged checkpoint or one signed by an unknown key;
- a checkpoint signed by a revoked key, so an operator can see which part of the trail lost its anchor.

### Database roles

Only the purge deletes audit rows. It must connect as a role holding `DELETE` on `audit_events`. The application's role holds only `INSERT` and `SELECT` there (`warden audit grants`, `warden.audit.grants`).

## 7. Anchors

**Code:** `src/warden/audit/anchor.py` (writing and reading anchors), `src/warden/audit/verify.py` (`verify_anchors`).

An anchor is a signed statement of the chain head at a moment: "row `head_id` had `row_hash` `head_hash` at `anchored_at`". It is written into the chain as an ordinary row, so the syslog forwarder sends it to the SIEM like any other, and from then on a copy exists that nobody with access only to the database can recall or edit. Checking the stored chain against those copies detects tail deletion and a rewrite of the chain, including one from genesis, back to the latest anchor the SIEM holds.

### Writing an anchor

`warden audit anchor` (or `warden.audit.anchor()`) reads the committed head, signs it with warden's active Ed25519 key (design D14), and appends a row with action `warden.audit.anchor` and outcome `success`. warden ships no scheduler: the product runs the command on its own schedule. With `--min-rows N` (`min_rows=N`) nothing is written unless at least N rows have been appended since the last anchor, so a scheduler that runs often anchors roughly every N rows and never anchors an idle trail twice. Writing an anchor needs only the application role's `INSERT` and `SELECT`, and a signing key. An empty trail is not anchored.

The head is read, signed and then appended without holding the chain lock in between, because signing borrows database connections of its own and a held lock could starve the pool. Rows recorded meanwhile may sit between the head and the anchor row; the anchor still attests the head as it was committed. When nothing else is recorded, the anchor row's `prev_hash` is the `head_hash` it signs.

The row's details are:

```json
{"anchor": {
  "version": 1,
  "head_id": 4120,
  "head_hash": "<hex row_hash of row head_id>",
  "anchored_at": "2026-10-28T03:00:00.123456Z",
  "key_id": "<signing key id>",
  "signature": "<base64url Ed25519 signature, unpadded>"
}}
```

`anchored_at` is the database's `clock_timestamp()` when the head was read, in the timestamp form of section 2. The signature covers

```
"warden.audit.anchor.v1\n" || canonical_json(anchor without "signature")
```

The domain string differs from the checkpoint's (`warden.audit.checkpoint.v1`), so a signature over one kind of artefact can never be presented as the other. Anchor details, like checkpoint details, are never truncated (section 4). An anchor's actor may be at most 64 characters, so that even with the longest host and application names the forwarded message fits the smallest syslog message cap warden accepts (1024 bytes) and the SIEM's copy is whole.

An anchor is accepted only in exactly this form: version 1, `head_id` a positive integer, `head_hash` 64 lower-case hex digits, `anchored_at` with six fractional digits and `Z`, a non-empty `key_id`, a 64-byte signature in unpadded base64url, and no other members.

### Reading anchors back

`warden audit verify --anchors FILE` reads one record per line from an export taken from the SIEM, in either of the forms warden emits:

- **NDJSON**, as `warden.audit.export` writes it: an object whose `action` is `warden.audit.anchor`, its `details` holding the anchor and its `id` the anchor row's id.
- **RFC 5424**, as the syslog forwarder sends it: a message whose structured data has a parameter `action="warden.audit.anchor"` and a `details` parameter holding the details as JSON. Any SD-ID is accepted, since a product may set its own; the anchor row's id is the MSGID. An octet count or a collector's prefix (its own receive time and host, say) before the message is skipped.

Every other line is ignored, so a whole export can be passed as it is. A line that is an anchor row but whose anchor cannot be read (a cut-short message, for example) is reported as malformed rather than skipped. A file with no anchors at all is refused.

### Verification rules

`verify_anchors` first verifies the chain exactly as `warden audit verify` does, then checks each anchor against the stored rows, all in the same REPEATABLE READ snapshot. For each anchor, in this order:

1. **Malformed:** the anchor could not be read.
2. **Signature:** the signature must verify with `verify_historical` over the message above. A key retired by routine rotation still counts. A revoked key does not, and is reported as such (`anchor_revoked_key`); any other failure, including an unknown key, is a bad signature (`anchor_signature`). No claim of an anchor that fails here is trusted.
3. **Head present:** if the row at `head_id` exists, its stored `row_hash` must equal `head_hash` (`matched`); otherwise the chain was rewritten (`head_hash`).
4. **Head purged:** if the row at `head_id` does not exist, the earliest checkpoint row still in the table whose `through_id` is at or after `head_id`, and whose own signature verifies, covers it. If that checkpoint's `through_id` is `head_id` itself, its `through_hash` must equal `head_hash` (`head_hash` if not). A covered anchor is reported `checkpointed`. With no such checkpoint, the row is missing (`head_missing`): the tail was deleted, or rows were removed without a checkpoint.

The command exits 0 only if the chain verifies and every anchor is `matched` or `checkpointed`. It reports anchors by line number and `head_id`, never row contents.

### What anchors show, and what they do not

- **Rewriting or altering any row up to an anchor's head**, with every later hash recomputed, changes the head's `row_hash`: `head_hash`. Altering a row without recomputing hashes is already found by the chain itself.
- **Deleting the tail** back past an anchor's head: `head_missing`.
- **Rewriting from genesis:** with the same ids, `head_hash`; as a fresh chain with new ids, `head_missing`.
- **A forged anchor**, or a genuine one edited to claim another head: `anchor_signature`.
- **Anchors survive retention.** After a purge removes an anchor's head (and the anchor row itself), the SIEM's copy is checked against the checkpoint that covers it, so anchors older than a purge keep verifying, across successive purges.
- **Residual exposure.** Rows written since the latest anchor the SIEM holds are protected only by the chain. A database administrator can still alter or delete them unseen, so the anchor interval bounds the exposure. And an anchor whose head lies strictly inside a purged range is accepted on the strength of the covering checkpoint: a rewrite made between that anchor and the purge, which the purge would then have verified and signed, is visible only if the anchors are checked before purging. Run `warden audit verify --anchors FILE` before each `warden audit purge`.