# Signed JSONL (SJSONL)

A Go library and CLI implementing SJSONL, a simple format for signing, diffing, and patching JSON data. SJSONL structures documents as [JSON Lines](https://jsonlines.org) and treats each document as a *set* of lines, so signing reduces to hashing lines and diffing reduces to set operations — no canonicalization and no signature embedding tricks.

The format was extracted from an application that needed JSON documents to be signed and efficiently updated. See the [SJSONL specification](https://openrevs.org/specs/sjsonl/) for the full format, including its goals and design rationale.

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
