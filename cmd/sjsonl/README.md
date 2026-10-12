# sjsonl - Signed JSONL Command Line Utility

A command line utility for working with signed JSONL (JSON Lines) documents. This tool provides cryptographic signing, verification, diffing, and patching capabilities for JSONL files.

## Installation

```bash
go build
```

## Usage

```bash
sjsonl <command> [arguments]
```

### Commands

#### keygen
Generates a new Ed25519 private key encoded as lowercase hex.

```bash
sjsonl keygen [filename]
```

**Examples:**
```bash
sjsonl keygen my_private.key
sjsonl keygen  # Creates private.key
```

The generated key file has secure permissions (0600) and contains a hex-encoded private key.

#### sign
Signs a JSONL file with an Ed25519 private key. The key can be provided via file, environment variable, or generated automatically.

```bash
sjsonl sign <input.jsonl> [-k keyfile]
```

**Examples:**
```bash
sjsonl sign data.jsonl -k my_private.key > signed_data.jsonl
sjsonl sign data.jsonl > signed_data.jsonl  # Uses SJSONL_PRIVATE_KEY env var
```

Key resolution order:
1. If `-k keyfile` is specified, reads the key from the file
2. If `SJSONL_PRIVATE_KEY` environment variable is set, uses that key
3. Otherwise, generates a new key pair for this operation

#### verify
Verifies a signed JSONL file and displays information about the signature.

```bash
sjsonl verify <signed.jsonl>
```

**Example:**
```bash
sjsonl verify signed_data.jsonl
```

**Output:**
```
Verification successful!
Hash: 51a3b004e0dfe95a72dae9956adc71ae
Signer ID: 13b63c616580d9e3635fb1d5414eb0b88017a8e8d3693c741479cec5bfdce4f6
Signer Key: 8e4a16bc4e443f860b5e29dddf02cc99a7ad43ff51b8b9e36e5cde1ed520e141
```

#### diff
Creates a patch document representing the differences between two signed JSONL files.

```bash
sjsonl diff <base.jsonl> <target.jsonl> > patch.jsonl
```

**Example:**
```bash
sjsonl diff base_signed.jsonl target_signed.jsonl > changes.patch
```

#### patch
Applies a patch document to a base signed JSONL file.

```bash
sjsonl patch <base.jsonl> <patch.jsonl> > result.jsonl
```

**Example:**
```bash
sjsonl patch base_signed.jsonl changes.patch > updated.jsonl
```

## Workflow Example

Here's a complete workflow demonstrating all operations:

1. **Generate a private key:**
   ```bash
   sjsonl keygen my_project.key
   ```

2. **Sign initial data:**
   ```bash
   sjsonl sign original.jsonl -k my_project.key > base_signed.jsonl
   ```

3. **Sign modified data:**
   ```bash
   sjsonl sign modified.jsonl -k my_project.key > target_signed.jsonl
   ```

4. **Create a patch between versions:**
   ```bash
   sjsonl diff base_signed.jsonl target_signed.jsonl > changes.patch
   ```

5. **Apply the patch to recreate the target:**
   ```bash
   sjsonl patch base_signed.jsonl changes.patch > result.jsonl
   ```

6. **Verify the result:**
   ```bash
   sjsonl verify result.jsonl
   ```

## Key Management

### Private Key Format
Private keys are stored as lowercase hex strings. This format is:
- Consistent with every other encoded value in the SJSONL format
- Unambiguous (no alphabet or padding variants)
- Safe for environment variables and command-line usage

### Security Considerations
- Private key files are created with 0600 permissions (owner read/write only)
- Keys can be stored in environment variables for CI/CD environments
- Each key generates a unique Signer ID for document attribution
- The same private key will always produce the same signatures for identical content

### Environment Variable Usage
```bash
export SJSONL_PRIVATE_KEY=$(cat my_private.key)
sjsonl sign document.jsonl > signed_document.jsonl
```

## Input Format

The input for the `sign` command should be valid JSONL (JSON Lines) format, where each line contains a valid JSON value:

```jsonl
{"id": 1, "name": "Alice"}
{"id": 2, "name": "Bob"}
42
"hello world"
[1, 2, 3]
null
```

## Output Format

Signed JSONL documents include a control line at the beginning containing cryptographic metadata:

```jsonl
{"sjsonl":"doc","version":"0.1","key":"...","sig":"..."}
{"id": 1, "name": "Alice"}
{"id": 2, "name": "Bob"}
42
"hello world"
[1, 2, 3]
null
```

## Security Features

- **Ed25519 Signatures**: Uses modern elliptic curve cryptography for signing
- **Content Integrity**: SHA-256 hashing ensures data hasn't been tampered with
- **Signer Identity**: Public key-based identification of document signers
- **Deterministic Verification**: Signatures can be verified by anyone with the public key

## Error Handling

The utility provides clear error messages for common issues:
- Invalid JSONL format
- Missing or corrupted signatures
- File not found errors
- Hash mismatches during patch application

Exit codes:
- `0`: Success
- `1`: Error (details written to stderr)

## Notes

- Information messages (hash, signer ID) are written to stderr to avoid interfering with output redirection
- The actual document content is written to stdout for easy piping and redirection
- Patch operations require both base and target documents to be signed
- Use the same private key for related documents to maintain consistent signer identity
- Private keys are sensitive - protect them appropriately and never commit them to version control