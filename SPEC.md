# Signed JSONL Specification

**Version 0.1**

This document specifies the SJSONL format for signing, diffing, and patching JSON Lines documents. For background and design rationale, see the [README](README.md).

## Documents

All SJSONL files, whether signed documents or patch files, are [JSON Lines](https://jsonlines.org) (JSONL) files, and all JSONL rules apply. A single trailing newline at the end of a file is permitted and ignored.

### Input

The input document (what is being signed) is treated as a line **set**:

- **Lines are unordered.** Documents with the same lines in a different order are equivalent, and line order in a signed document is not significant.
- **Duplicate lines are not allowed.** For this test, a line's content has leading and trailing whitespace stripped.
- **Every line must be valid JSON.** Empty lines are not allowed.

Those are the only input requirements beyond those of JSON Lines. The following is a valid input:

```json
{"name": "Alice", "age": 42}
{"name": "Bob", "age": 30}
{"address": {"street": "Main", "number":12}}
null
95
```

## Line hashes

Each line's hash is the SHA256 of the line's bytes with leading and trailing whitespace removed.

All binary values in SJSONL — hashes, keys, and signatures — are encoded as lowercase hex wherever they appear as strings.

## Header line

The first line of a signed document or patch file MUST be a header line: a JSON object with the following fields, some of which apply only to patches.

| Field | Applies to | Description |
|-------|-----------|-------------|
| `sjsonl` | both | Marker and file type: `"doc"` for a signed document, `"patch"` for a patch |
| `version` | both | Format version. Currently the only supported version is `"0.1"` |
| `key` | both | The Ed25519 public key, encoded as lowercase hex |
| `sig` | both | The Ed25519 signature, encoded as lowercase hex. For patches, this is the signature of the **patched** document, not of the patch itself |
| `base` | patch only | The document hash of the base document, identifying the expected source of the patch |
| `target` | patch only | The document hash of the patched (target) document |
| `rm` | patch only | A JSON array of hash prefixes identifying lines to remove from the base document |

The header line is not part of the signed line set.

## Signing

The signature is computed as follows:

1. Compute the hash of each line as described above, excluding the header line and an optional empty last line (if the file ends with `\n`).
2. Sort the hashes in ascending order.
3. Concatenate the sorted hashes, as raw 32-byte values, into a single byte string. This is the message to be signed. (An empty document produces an empty message, which is still signable.)
4. Sign the message with the signer's Ed25519 private key, or verify it against the `sig` and `key` fields of the header line.

A signed document is the input document plus the header line:

```json
{"sjsonl":"doc","version":"0.1","key":"1ddb79531fac6085eb572eb63c9ed3cd84a85e08c08f0a06f283b07e56e041a8","sig":"e00dd056df7f0ef012290b97953a25a93e61255121396d8fc8d83ce2e71b5b97584029ba3f98af941fcdbcc79a552632b592bfc70a01e57fc3547a5e6232780b"}
{"name": "Bob", "age": 30}
null
{"name": "Alice", "age": 42}
{"address": {"street": "Main", "number":12}}
95
```

### Document hash

A document's hash is the first 16 bytes of the SHA256 of the signing message from step 3 above, encoded as lowercase hex. It identifies a specific line set and is used as the `base` and `target` references in patches and for general purpose document identification.

## Patching

Patching turns a base/source document into a new (target) document given a patch file. Two documents may be *diffed* to generate a patch. Because documents are line sets, a diff is a set operation: find the lines to remove and the lines to add. Only whole-line operations are supported — if any part of a line changes, the whole line is replaced.

A patch file consists of:

- A header line with `sjsonl` set to `"patch"`, carrying:
  - `base` — the document hash of the base document
  - `target` — the document hash of the patched (target) document
  - `rm` — hash prefixes of the lines to remove
  - `key` and `sig` — the signature data for the **patched** (target) document
- The lines to add, one per line, verbatim

The `base` and `target` hashes make a patch self-describing as an edge in a version graph: consumers can select the right patch for a document they hold, and chain patches (one patch's `target` feeding the next patch's `base`) without applying them. The `target` hash is advisory — the signature remains the authority on the patched result, and a `target` that disagrees with it is exposed by signature verification at apply time.

Example — a patch that changes Alice's age in the document above:

```json
{"sjsonl":"patch","version":"0.1","key":"1ddb79531fac6085eb572eb63c9ed3cd84a85e08c08f0a06f283b07e56e041a8","sig":"c913a7f3e48bbc5c8c50e6446c1292e9d96ec04d776c45404324ee3e0fa999a606d72bfce25125d733c760379d80b0c0e7a710dc53c1ef30af1a164610a24505","base":"20728fa9354b71b9b05f34b3e7bf8f81","target":"775a21e81092bede93eb474903b3a8a7","rm":["7a"]}
{"name": "Alice", "age": 50}
```

### Deletions

Deletions are represented as a JSON array of hash prefixes. Each prefix is a string of lowercase hex characters.

**Consumers** MUST delete every line of the base document whose hash starts with any listed prefix. A prefix may match multiple lines. It is an error if a prefix matches no lines.

**Generators** may use any prefix length, from a single character up to the full hash. The only requirement is that each prefix match exactly the lines intended for deletion — the generator is responsible for checking its prefixes against the base document. Any strategy that satisfies this is valid: emitting full hashes, computing minimal unique prefixes, or simply truncating to a fixed length and extending on the rare unintended match (16 characters is recommended — at 64 bits, an accidental collision with another line's hash is negligible at any practical document size).

Note that an over-matching prefix fails closed: the unintended deletion causes signature verification of the patched document to fail, so a bad patch is rejected rather than silently corrupting data.

An empty array is valid and deletes nothing (a pure-additions patch). A zero-length prefix (`""`) is also valid and matches every line, deleting the entire base document; this makes a full-replacement patch expressible without a separate operation.

### Applying a patch

1. Verify that the `base` field matches the base document's hash.
2. Remove every line from the base document whose hash matches an `rm` prefix.
3. Add each of the patch's data lines to the set. All input rules apply to the result (no duplicates, etc.).
4. Form the result document from the patch's `key` and `sig` as a `"doc"` header line plus the resulting line set, and verify its signature as described in [Signing](#signing).

Because the patch carries the signature of the target document, a successfully applied and verified patch yields a fully signed document. This doubles as patch verification, and is why the patch file itself is not signed.
