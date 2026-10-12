package sjsonl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/tidwall/gjson"
)

const (
	// Operations
	sign int = iota + 1
	parse
	patch
)

const (
	jsonVersion = "version"
	jsonKey     = "key"
	jsonSig     = "sig"
	jsonRm      = "rm"
	jsonBase    = "base"
	jsonTarget  = "target"
	jsonSJSONL  = "sjsonl"
)

const formatVersion = "0.1"

// Sign creates a signed JSONL document from the given data and private key.
func Sign(data []byte, privateKey ed25519.PrivateKey) ([]byte, Info, error) {
	lines, err := split(data)
	if err != nil {
		return nil, Info{}, err
	}

	jsonl, err := linesParseCore(lines, privateKey, sign)
	if err != nil {
		return nil, Info{}, err
	}

	return jsonl.JSON(), jsonl.info, nil
}

// Verify verifies a signed JSONL document and returns information about it.
func Verify(data []byte) (Info, error) {
	jsonl, err := Parse(data)
	if err != nil {
		return Info{}, err
	}

	return jsonl.info, nil
}

// Diff creates a patch document representing the difference between base and target.
func Diff(base, target []byte) ([]byte, error) {
	baseJsonl, err := Parse(base)
	if err != nil {
		return nil, err
	}

	targetJsonl, err := Parse(target)
	if err != nil {
		return nil, err
	}

	patch, err := baseJsonl.Diff(targetJsonl)
	if err != nil {
		return nil, err
	}

	return patch.JSON(), nil
}

// Patch applies a patch document to a base document and returns the result.
func Patch(base, patch []byte) ([]byte, Info, error) {
	baseJsonl, err := Parse(base)
	if err != nil {
		return nil, Info{}, err
	}

	patchJsonl, err := ParsePatch(patch)
	if err != nil {
		return nil, Info{}, err
	}

	result, err := baseJsonl.Patch(patchJsonl)
	if err != nil {
		return nil, Info{}, err
	}

	return result.JSON(), result.info, nil
}

type JSONL struct {
	lines []hashedLine
	ctl   controlLine
	info  Info
}

type Info struct {
	Hash      string
	SignerID  string
	SignerKey ed25519.PublicKey
}

type controlLine struct {
	ctlType   int
	publicKey ed25519.PublicKey
	signature []byte
	base      string
	target    string
	rm        []string
}

func (ctl controlLine) JSON() string {
	docType := "doc"
	if ctl.ctlType == patch {
		docType = "patch"
	}

	controlLineJSON := struct {
		SJSONL  string    `json:"sjsonl"`
		Version string    `json:"version"`
		Key     string    `json:"key"`
		Sig     string    `json:"sig"`
		Base    string    `json:"base,omitempty"`
		Target  string    `json:"target,omitempty"`
		Rm      *[]string `json:"rm,omitempty"`
	}{
		SJSONL:  docType,
		Version: formatVersion,
		Key:     hex.EncodeToString(ctl.publicKey),
		Sig:     hex.EncodeToString(ctl.signature),
		Base:    ctl.base,
		Target:  ctl.target,
	}

	// Patches always carry an rm array, even when empty; docs never do.
	if ctl.ctlType == patch {
		deletions := ctl.rm
		if deletions == nil {
			deletions = []string{}
		}
		controlLineJSON.Rm = &deletions
	}

	j, err := json.Marshal(controlLineJSON)
	if err != nil {
		return ""
	}
	return string(j)
}

type hashedLine struct {
	line []byte
	hash string
}

var (
	ErrEmptyLine             = errors.New("empty JSON line")
	ErrInvalidJSON           = errors.New("not a valid JSON object")
	ErrMultiLine             = errors.New("JSON must be single line")
	ErrDuplicateLine         = errors.New("duplicate JSON line")
	ErrBadKeyFormat          = errors.New("bad key format")
	ErrBadSigFormat          = errors.New("bad signature format")
	ErrSigVerificationFailed = errors.New("signature verification failed")
	ErrMissingSignature      = errors.New("missing signature")
	ErrControlLineNotFound   = errors.New("control line not found")
	ErrRmFormatError         = errors.New("bad rm format")
)

// New creates a new JSONL instance from the given data and private key.
func New(data []byte, privateKey ed25519.PrivateKey) (*JSONL, error) {
	lines, err := split(data)
	if err != nil {
		return nil, err
	}

	return linesParseCore(lines, privateKey, sign)
}

// Parse creates a new JSONL instance from an existing SJSONL encoding.
func Parse(data []byte) (*JSONL, error) {
	lines, err := split(data)
	if err != nil {
		return nil, err
	}

	return linesParseCore(lines, nil, parse)
}

// ParsePatch creates a new JSONL instance from an existing SJSONL encoding.
func ParsePatch(data []byte) (*JSONL, error) {
	lines, err := split(data)
	if err != nil {
		return nil, err
	}

	return linesParseCore(lines, nil, patch)
}

func split(data []byte) ([][]byte, error) {
	lines := bytes.Split(data, []byte("\n"))

	// Allow and strip a single trailing newline (which here results in an empty line), per JSONL definition
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}

	if len(lines) == 0 {
		return nil, errors.New("empty JSONL")
	}

	return lines, nil
}

func (jsonl *JSONL) JSON() []byte {
	var buf bytes.Buffer

	buf.WriteString(jsonl.ctl.JSON())
	buf.WriteByte('\n')

	for _, line := range jsonl.lines {
		buf.Write(line.line)
		buf.WriteByte('\n')
	}

	return buf.Bytes()
}

// Info returns metadata about the document: its hash and signer.
func (j *JSONL) Info() Info {
	return j.info
}

func (j *JSONL) hash() string {
	return hashDocument(j.lines)
}

func linesParseCore(lines [][]byte, privateKey ed25519.PrivateKey, mode int) (*JSONL, error) {
	var ctl *controlLine
	lineOffset := 1 // report 1-based file line numbers
	if mode != sign {
		var err error
		ctl, err = parseControlLine(lines[0])
		if err != nil {
			return nil, err
		}
		lines = lines[1:]
		lineOffset = 2 // account for the header line
	}

	hashes := map[[sha256.Size]byte]int{}

	hashedLines := make([]hashedLine, 0, len(lines))
	for i, line := range lines {
		line, err := cleanAndValidate(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+lineOffset, err)
		}

		hash := sha256.Sum256(line)
		if first, ok := hashes[hash]; ok {
			return nil, fmt.Errorf("line %d: %w (first seen at line %d): %s",
				i+lineOffset, ErrDuplicateLine, first, snippet(line))
		}
		hashes[hash] = i + lineOffset

		hashedLines = append(hashedLines, hashedLine{
			line: line,
			hash: hex.EncodeToString(hash[:]),
		})
	}
	slices.SortFunc(hashedLines, func(a, b hashedLine) int {
		return strings.Compare(a.hash, b.hash)
	})

	ret := &JSONL{
		lines: hashedLines,
	}

	switch mode {
	case parse:
		if ctl.ctlType != sign {
			return nil, ErrMissingSignature
		}
		ret.ctl = *ctl
		msg := concatLineHashes(hashedLines)
		if !ed25519.Verify(ctl.publicKey, msg, ctl.signature) {
			return nil, ErrSigVerificationFailed
		}
	case patch:
		ret.ctl = *ctl
	case sign:
		ctl = &controlLine{
			ctlType:   sign,
			publicKey: privateKey.Public().(ed25519.PublicKey),
			signature: signLines(hashedLines, privateKey),
		}
		ret.ctl = *ctl
	default:
		panic(fmt.Sprintf("invalid mode: %d", mode))
	}

	ret.info = newInfo(ret)

	return ret, nil
}

func parseControlLine(line []byte) (*controlLine, error) {
	if !gjson.ValidBytes(line) {
		return nil, ErrInvalidJSON
	}

	result := gjson.ParseBytes(line)
	ctlType := result.Get(jsonSJSONL).String()

	if ctlType != "doc" && ctlType != "patch" {
		return nil, fmt.Errorf("unknown sjsonl type %q", ctlType)
	}

	// Validate public key format and length
	pubKeyStr := result.Get(jsonKey).String()
	pubKeyBytes, err := decodeHex(pubKeyStr)
	if err != nil {
		return nil, ErrBadKeyFormat
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, ErrBadKeyFormat
	}

	// Validate signature format and length
	sigStr := result.Get(jsonSig).String()
	sigBytes, err := decodeHex(sigStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature decoding: %w", ErrBadSigFormat, err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: invalid signature size: %d", ErrBadSigFormat, len(sigBytes))
	}

	ctl := &controlLine{
		publicKey: pubKeyBytes,
		signature: sigBytes,
	}

	if ctlType == "doc" {
		ctl.ctlType = sign

		return ctl, nil
	}

	// Parse additional data for Patches
	ctl.ctlType = patch

	base := result.Get(jsonBase)
	if !base.Exists() {
		return nil, errors.New("missing 'base'")
	}
	ctl.base = base.String()

	target := result.Get(jsonTarget)
	if !target.Exists() {
		return nil, errors.New("missing 'target'")
	}
	ctl.target = target.String()

	rmRaw := result.Get(jsonRm)
	if !rmRaw.Exists() {
		return nil, errors.New("missing 'rm'")
	}
	slog.Debug("rmRaw", "value", rmRaw.String())
	deletions, err := parseRm(rmRaw)
	if err != nil {
		return nil, err
	}

	ctl.rm = deletions

	return ctl, nil
}

func newInfo(jsonl *JSONL) Info {
	hash := hashDocument(jsonl.lines)
	signerKey := jsonl.ctl.publicKey
	idRaw := sha256.Sum256(signerKey)
	signerID := hex.EncodeToString(idRaw[:])

	return Info{
		Hash:      hash,
		SignerID:  signerID,
		SignerKey: signerKey,
	}
}

// cleanAndValidate strips whitespace and validates a JSON line.
func cleanAndValidate(line []byte) ([]byte, error) {
	line = bytes.TrimSpace(line)

	if len(line) == 0 {
		return nil, ErrEmptyLine
	}

	// Check for newlines within the JSON (must be single line)
	if bytes.ContainsAny(line, "\r\n") {
		return nil, ErrMultiLine
	}

	// TODO: necessary?
	if !gjson.ValidBytes(line) {
		return nil, ErrInvalidJSON
	}

	return line, nil
}

// signLines signs the given lines using the provided private key. It assumes
// that the lines are already sorted by their hash.
func signLines(lines []hashedLine, privateKey ed25519.PrivateKey) []byte {
	if len(lines) == 0 {
		return ed25519.Sign(privateKey, nil)
	}

	msg := concatLineHashes(lines)

	return ed25519.Sign(privateKey, msg)
}

func hashDocument(lines []hashedLine) string {
	msg := concatLineHashes(lines)
	h := sha256.Sum256(msg)
	return hex.EncodeToString(h[:sha256.Size/2])
}

func parseRm(result gjson.Result) ([]string, error) {
	if !result.IsArray() {
		return nil, ErrRmFormatError
	}

	elems := result.Array()
	deletions := make([]string, 0, len(elems))
	for _, elem := range elems {
		if elem.Type != gjson.String || !isLowerHex(elem.String()) {
			return nil, ErrRmFormatError
		}
		deletions = append(deletions, elem.String())
	}

	return deletions, nil
}

// isLowerHex reports whether s consists only of lowercase hex characters.
// Uppercase is rejected so every value has exactly one valid encoding.
func isLowerHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// decodeHex decodes a lowercase hex string.
func decodeHex(s string) ([]byte, error) {
	if !isLowerHex(s) {
		return nil, errors.New("not lowercase hex")
	}
	return hex.DecodeString(s)
}

// snippet returns a truncated copy of line suitable for error messages.
func snippet(line []byte) string {
	const maxLen = 60
	if len(line) <= maxLen {
		return string(line)
	}
	return string(line[:maxLen]) + "..."
}

// concatLineHashes concatenates the given lines' hashes into a single byte slice.
// It assumes (and verifies) that the lines are already sorted by their hash.
func concatLineHashes(lines []hashedLine) []byte {
	msg := make([]byte, len(lines)*sha256.Size)

	var lastHash string
	for i, line := range lines {
		if i > 0 && strings.Compare(line.hash, lastHash) < 0 {
			panic("lines are not sorted")
		}
		hash, err := hex.DecodeString(line.hash)
		if err != nil {
			panic(err)
		}
		copy(msg[i*sha256.Size:], hash)
		lastHash = line.hash
	}

	return msg
}
