package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"

	"github.com/kalafut/sjsonl"
)

func main() {
	var level slog.LevelVar
	level.Set(slog.LevelDebug)

	logger := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: &level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				return slog.String(slog.TimeKey, a.Value.Time().Format("15:04:05"))
			}
			return a
		},
	})
	slog.SetDefault(slog.New(logger))

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "keygen":
		handleKeygen()
	case "sign":
		handleSign()
	case "verify":
		handleVerify()
	case "diff":
		handleDiff()
	case "patch":
		handlePatch()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`sjsonl - A command line utility for signed JSONL operations

Usage:
  sjsonl keygen [filename]        - Generate a new Ed25519 private key
  sjsonl sign <input.jsonl> [-k keyfile] - Sign a JSONL file with a private key
  sjsonl verify <signed.jsonl>    - Verify a signed JSONL file
  sjsonl diff <base.jsonl> <target.jsonl> - Create a patch between two JSONL files
  sjsonl patch <base.jsonl> <patch.jsonl> - Apply a patch to a base JSONL file

Commands:
  keygen   Generates a new Ed25519 private key (hex encoded)
  sign     Signs the input JSONL file with a private key from file or env var
  verify   Verifies a signed JSONL file and displays information about it
  diff     Creates a patch document representing differences between two files
  patch    Applies a patch document to a base document

Examples:
  sjsonl keygen private.key
  sjsonl sign data.jsonl -k private.key > signed.jsonl
  sjsonl sign data.jsonl > signed.jsonl  # Uses SJSONL_PRIVATE_KEY env var
  sjsonl verify signed.jsonl
  sjsonl diff base.jsonl target.jsonl > patch.jsonl
  sjsonl patch base.jsonl patch.jsonl > result.jsonl
`)
}

func handleKeygen() {
	var filename string
	if len(os.Args) >= 3 {
		filename = os.Args[2]
	} else {
		filename = "private.key"
	}

	// Generate a new key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
		os.Exit(1)
	}

	// Encode private key as hex
	encoded := hex.EncodeToString(privateKey)

	err = os.WriteFile(filename, []byte(encoded), 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing key file %s: %v\n", filename, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Private key generated and saved to: %s\n", filename)
}

func handleSign() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: sjsonl sign <input.jsonl> [-k keyfile]\n")
		os.Exit(1)
	}

	filename := os.Args[2]
	var keyFile string

	// Parse optional -k flag
	if len(os.Args) >= 5 && os.Args[3] == "-k" {
		keyFile = os.Args[4]
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filename, err)
		os.Exit(1)
	}

	var privateKey ed25519.PrivateKey

	if keyFile != "" {
		// Read private key from file
		privateKey, err = readPrivateKeyFromFile(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading private key from %s: %v\n", keyFile, err)
			os.Exit(1)
		}
	} else {
		// Try to read from environment variable
		privateKey, err = readPrivateKeyFromEnv()
		if err != nil {
			// Fall back to generating a new key pair
			fmt.Fprintf(os.Stderr, "No key file specified and SJSONL_PRIVATE_KEY not set, generating new key pair\n")
			_, privateKey, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
				os.Exit(1)
			}
		}
	}

	signed, info, err := sjsonl.Sign(data, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing JSONL: %v\n", err)
		os.Exit(1)
	}

	// Output the signed document to stdout
	os.Stdout.Write(signed)

	// Print info to stderr so it doesn't interfere with piping
	fmt.Fprintf(os.Stderr, "Signed successfully\n")
	fmt.Fprintf(os.Stderr, "Hash: %s\n", info.Hash)
	fmt.Fprintf(os.Stderr, "Signer ID: %s\n", info.SignerID)
}

func handleVerify() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: sjsonl verify <signed.jsonl>\n")
		os.Exit(1)
	}

	filename := os.Args[2]
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filename, err)
		os.Exit(1)
	}

	info, err := sjsonl.Verify(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Verification successful!\n")
	fmt.Printf("Hash: %s\n", info.Hash)
	fmt.Printf("Signer ID: %s\n", info.SignerID)
	fmt.Printf("Signer Key: %x\n", info.SignerKey)
}

func handleDiff() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: sjsonl diff <base.jsonl> <target.jsonl>\n")
		os.Exit(1)
	}

	baseFile := os.Args[2]
	targetFile := os.Args[3]

	baseData, err := os.ReadFile(baseFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading base file %s: %v\n", baseFile, err)
		os.Exit(1)
	}

	targetData, err := os.ReadFile(targetFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading target file %s: %v\n", targetFile, err)
		os.Exit(1)
	}

	patch, err := sjsonl.Diff(baseData, targetData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating diff: %v\n", err)
		os.Exit(1)
	}

	// Output the patch to stdout
	os.Stdout.Write(patch)

	// Print success message to stderr
	fmt.Fprintf(os.Stderr, "Patch created successfully\n")
}

func handlePatch() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: sjsonl patch <base.jsonl> <patch.jsonl>\n")
		os.Exit(1)
	}

	baseFile := os.Args[2]
	patchFile := os.Args[3]

	baseData, err := os.ReadFile(baseFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading base file %s: %v\n", baseFile, err)
		os.Exit(1)
	}

	patchData, err := os.ReadFile(patchFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading patch file %s: %v\n", patchFile, err)
		os.Exit(1)
	}

	result, info, err := sjsonl.Patch(baseData, patchData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error applying patch: %v\n", err)
		os.Exit(1)
	}

	// Output the result to stdout
	os.Stdout.Write(result)

	// Print info to stderr
	fmt.Fprintf(os.Stderr, "Patch applied successfully\n")
	fmt.Fprintf(os.Stderr, "Result Hash: %s\n", info.Hash)
	fmt.Fprintf(os.Stderr, "Signer ID: %s\n", info.SignerID)
}

func readPrivateKeyFromFile(filename string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Decode hex
	privateKey, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	return ed25519.PrivateKey(privateKey), nil
}

func readPrivateKeyFromEnv() (ed25519.PrivateKey, error) {
	keyStr := os.Getenv("SJSONL_PRIVATE_KEY")
	if keyStr == "" {
		return nil, fmt.Errorf("SJSONL_PRIVATE_KEY environment variable not set")
	}

	// Decode hex
	privateKey, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key from environment: %v", err)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size from environment: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	return ed25519.PrivateKey(privateKey), nil
}
