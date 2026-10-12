# Signed JSONL (SJSONL)

SJSONL is a simple format for signing, diffing, and patching JSON data, along with a Go library and CLI implementing it. It works by structuring documents as [JSON Lines](https://jsonlines.org) and treating each document as a *set* of lines. Signing then reduces to hashing lines, and diffing reduces to set operations. There's no canonicalization and no signature embedding tricks.

The format was extracted from an application that needed JSON documents to be signed and efficiently updated. See [SPEC.md](SPEC.md) for the full format specification.

## Goals

- Documents can be signed and verified against a public key
- Documents can be diffed and patched, including by third parties who cannot sign
- Familiar formats and encodings (JSONL, SHA256, Ed25519, hex)
- Simple design and easy implementation

## Why not just sign JSON?

[Signing JSON is difficult](https://www.latacora.com/blog/2019/07/24/how-not-to/). You can't store a signature inside a document without changing it, so you're left with hacks to embed and extract it. Canonicalizing JSON is non-standard, complicated, and inconsistently supported, so the usual advice is "don't sign JSON" — sign the bytes and convey the signature separately.

Diffing and patching are no easier. A textual diff is useless when the document is one long line, and semantic diffs like JSON merge-patch conflict with byte-oriented signing, since a patched document can be re-encoded any number of ways.

Structuring the document as a set of lines sidesteps all of this:

- **Signing is simple.** Each line is hashed as an exact byte sequence; the sorted hashes are signed. The signature lives in a header line that isn't part of the signed content, so nothing needs to be embedded or extracted.
- **Diff/patch is simple.** A diff between two documents is just the set of lines removed and added. Removals are identified by short hash prefixes.
- **Patches carry the target's signature**, so applying a patch yields a fully signed document — third parties can generate and apply patches without ever holding a signing key.

The tradeoff is that your data must fit a line-centric structure (a catalog, blog posts, reviews, paragraph blocks, …).

Line orientation also helps on the server side:

- Because signing covers a *set* of lines rather than a specific byte sequence, servers can offer patches between arbitrary versions.
- Multiple versions of a document can be stored efficiently by deduplicating lines across revisions.

## Quick start

```bash
go build -o sjsonl ./cmd/sjsonl

./sjsonl keygen private.key
./sjsonl sign data.jsonl -k private.key > signed.jsonl
./sjsonl verify signed.jsonl
./sjsonl diff base.jsonl target.jsonl > patch.jsonl
./sjsonl patch base.jsonl patch.jsonl > result.jsonl
```

The `sign` command resolves its key in order: `-k keyfile` flag, then the `SJSONL_PRIVATE_KEY` environment variable, then auto-generating a new key pair.

## Library

```go
import sjsonl "github.com/kalafut/sjsonl"

signed, info, err := sjsonl.Sign(data, privateKey)
info, err := sjsonl.Verify(signed)
patch, err := sjsonl.Diff(base, target)
result, info, err := sjsonl.Patch(base, patch)
```

`Info` reports the document hash, the signer's public key, and a signer ID (SHA256 of the public key).
