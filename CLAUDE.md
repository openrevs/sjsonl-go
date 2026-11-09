# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SJSONL is a Go library and CLI tool for cryptographically signing, verifying, diffing, and patching JSON Lines (JSONL) documents using Ed25519 signatures. Documents are treated as line **sets** (unordered, no duplicates). The specification, including design rationale, now lives in the OpenRevs website repo at `../website/specs/sjsonl.md` (published at https://openrevs.org/specs/sjsonl/).

## Build & Test Commands

```bash
# Run all tests (from repo root)
go test ./...

# Run a single test
go test -run TestName ./...

# Run benchmarks
go test -bench=. -benchmem ./...

# Build the CLI tool
go build -o cmd/sjsonl/sjsonl ./cmd/sjsonl
```

## Project Structure

A single Go module (`github.com/openrevs/sjsonl-go`):

- **Root package** — the library
- **`cmd/sjsonl/`** — CLI tool (`go run ./cmd/sjsonl`)

### Key source files

| File | Purpose |
|------|---------|
| `apiv2.go` | Public API: `Sign`, `Verify`, `Diff`, `Patch` functions and `Info` struct |
| `jsonlines.go` | Core: JSONL parsing, signing, verification, line hashing, control line handling |
| `patch.go` | Diff/patch logic, unique prefix finding algorithm |
| `util.go` | Helpers: hash concatenation, JSON building |
| `cmd/sjsonl/main.go` | CLI with subcommands: `keygen`, `sign`, `verify`, `diff`, `patch` |

## Architecture

**Signing flow:** split input into lines → validate each as JSON → SHA256 hash each line → sort hashes lexicographically → concatenate into message → Ed25519 sign → output control line + data lines.

**Patching flow:** diff finds added/removed lines between base and target → removed lines represented as minimal hash prefixes → patch file contains a control line (base and target hashes, `rm` hash prefixes, target signature) + new lines to add.

Key design points:
- Lines are a **set** — order doesn't matter, duplicates are errors
- Hashes (line hashes, document hash, `base`/`target`, `rm` prefixes, Signer ID) are lowercase hex; keys and signatures are standard padded base64, decoded strictly so only the canonical encoding is accepted
- The `JSONL` struct holds parsed `hashedLine` entries and a `controlLine` with signature metadata
- The internal `linesParseCore` function handles sign, parse, and patch modes via a mode parameter
- `gjson` is used for JSON validation (faster than stdlib `json.Valid`)

## CLI Key Resolution

The `sign` command resolves the private key in order: `-k keyfile` flag → `SJSONL_PRIVATE_KEY` env var → auto-generate new key pair.
