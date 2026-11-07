package sjsonl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestValid(t *testing.T) {
	require := require.New(t)
	data, err := os.ReadFile("testdata/valid_input.jsonl")
	require.NoError(err)

	_, _, err = Sign(data, testKey())
	require.NoError(err)
}

func TestParseControlLine(t *testing.T) {
	fakeKey := b64(0x6b, 32)
	fakeSig := b64(0x73, 64)
	fakeBase := strings.Repeat("ba", 32)
	fakeTarget := strings.Repeat("7a", 32)

	tests := []struct {
		name      string
		input     []byte
		expectErr bool
		errType   error
		ctlType   int
	}{
		{
			name:      "missing key field",
			input:     []byte(`{"sjsonl": "doc"}`),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   sign,
		},
		{
			name:      "missing sig field",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s"}`, fakeKey),
			expectErr: true,
			errType:   ErrBadSigFormat,
			ctlType:   sign,
		},
		{
			name:      "invalid base64 in key",
			input:     []byte(`{"sjsonl": "doc", "key": "invalid@b64!", "sig": "abcd"}`),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   sign,
		},
		{
			name:      "invalid base64 in sig",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "invalid@b64!"}`, fakeKey),
			expectErr: true,
			errType:   ErrBadSigFormat,
			ctlType:   sign,
		},
		{
			name:      "hex key",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "%s"}`, strings.Repeat("6b", 32), fakeSig),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   sign,
		},
		{
			name:      "non-canonical key (trailing bits set)",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "%s"}`, setTrailingBits(fakeKey), fakeSig),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   sign,
		},
		{
			name:      "non-canonical sig (trailing bits set)",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "%s"}`, fakeKey, setTrailingBits(fakeSig)),
			expectErr: true,
			errType:   ErrBadSigFormat,
			ctlType:   sign,
		},
		{
			name:      "unpadded key",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "%s"}`, strings.TrimRight(fakeKey, "="), fakeSig),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   sign,
		},
		{
			name:      "unpadded sig",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "%s"}`, fakeKey, strings.TrimRight(fakeSig, "=")),
			expectErr: true,
			errType:   ErrBadSigFormat,
			ctlType:   sign,
		},
		{
			name:      "url-safe alphabet in key",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "%s"}`, base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)), fakeSig),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   sign,
		},
		{
			name:      "embedded newline in key",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s\n%s", "sig": "%s"}`, fakeKey[:20], fakeKey[20:], fakeSig),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   sign,
		},
		{
			name:      "wrong length public key - too short",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "abcd", "sig": "%s"}`, fakeSig),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   sign,
		},
		{
			name:      "wrong length signature - too short",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "abcd"}`, fakeKey),
			expectErr: true,
			errType:   ErrBadSigFormat,
			ctlType:   sign,
		},
		{
			name:      "valid signature format",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "%s"}`, fakeKey, fakeSig),
			expectErr: false,
			ctlType:   sign,
		},
		{
			name:      "bare patch control line",
			input:     []byte(`{"sjsonl": "patch"}`),
			expectErr: true,
			errType:   ErrBadDocHashFormat,
			ctlType:   patch,
		},
		{
			name:      "doc missing key and sig",
			input:     []byte(`{"sjsonl": "doc"}`),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   sign,
		},
		{
			name:      "doc missing sig",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s"}`, fakeKey),
			expectErr: true,
			errType:   ErrBadSigFormat,
			ctlType:   sign,
		},
		{
			name:      "patch with key but no sig",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": "%s", "base": "%s", "target": "%s", "rm": []}`, fakeKey, fakeBase, fakeTarget),
			expectErr: true,
			errType:   ErrBadSigFormat,
			ctlType:   patch,
		},
		{
			name:      "patch with sig but no key",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "sig": "%s", "base": "%s", "target": "%s", "rm": []}`, fakeSig, fakeBase, fakeTarget),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   patch,
		},
		{
			name:      "patch with non-string key",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": null, "sig": "%s", "base": "%s", "target": "%s", "rm": []}`, fakeSig, fakeBase, fakeTarget),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   patch,
		},
		{
			name:      "empty key field",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "", "sig": "%s"}`, fakeSig),
			expectErr: true,
			errType:   ErrBadKeyFormat,
			ctlType:   sign,
		},
		{
			name:      "empty sig field",
			input:     fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": ""}`, fakeKey),
			expectErr: true,
			errType:   ErrBadSigFormat,
			ctlType:   sign,
		},
		{
			name:      "valid patch control line",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": "%s", "sig": "%s", "base": "%s", "target": "%s", "rm": ["abc"]}`, fakeKey, fakeSig, fakeBase, fakeTarget),
			expectErr: false,
			ctlType:   patch,
		},
		{
			name:      "patch control line missing target",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": "%s", "sig": "%s", "base": "%s", "rm": ["abc"]}`, fakeKey, fakeSig, fakeBase),
			expectErr: true,
			errType:   ErrBadDocHashFormat,
			ctlType:   patch,
		},
		{
			name:      "patch control line missing base",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": "%s", "sig": "%s", "target": "%s", "rm": ["abc"]}`, fakeKey, fakeSig, fakeTarget),
			expectErr: true,
			errType:   ErrBadDocHashFormat,
			ctlType:   patch,
		},
		{
			name:      "patch control line empty target",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": "%s", "sig": "%s", "base": "%s", "target": "", "rm": ["abc"]}`, fakeKey, fakeSig, fakeBase),
			expectErr: true,
			errType:   ErrBadDocHashFormat,
			ctlType:   patch,
		},
		{
			name:      "patch control line truncated (16-byte) target",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": "%s", "sig": "%s", "base": "%s", "target": "%s", "rm": ["abc"]}`, fakeKey, fakeSig, fakeBase, fakeTarget[:32]),
			expectErr: true,
			errType:   ErrBadDocHashFormat,
			ctlType:   patch,
		},
		{
			name:      "patch control line truncated (16-byte) base",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": "%s", "sig": "%s", "base": "%s", "target": "%s", "rm": ["abc"]}`, fakeKey, fakeSig, fakeBase[:32], fakeTarget),
			expectErr: true,
			errType:   ErrBadDocHashFormat,
			ctlType:   patch,
		},
		{
			name:      "patch control line overlong target",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": "%s", "sig": "%s", "base": "%s", "target": "%s00", "rm": ["abc"]}`, fakeKey, fakeSig, fakeBase, fakeTarget),
			expectErr: true,
			errType:   ErrBadDocHashFormat,
			ctlType:   patch,
		},
		{
			name:      "patch control line uppercase target",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": "%s", "sig": "%s", "base": "%s", "target": "%s", "rm": ["abc"]}`, fakeKey, fakeSig, fakeBase, strings.ToUpper(fakeTarget)),
			expectErr: true,
			errType:   ErrBadDocHashFormat,
			ctlType:   patch,
		},
		{
			name:      "patch control line non-string target",
			input:     fmt.Appendf(nil, `{"sjsonl": "patch", "key": "%s", "sig": "%s", "base": "%s", "target": null, "rm": ["abc"]}`, fakeKey, fakeSig, fakeBase),
			expectErr: true,
			errType:   ErrBadDocHashFormat,
			ctlType:   patch,
		},
	}

	// Generate real ed25519 keys for additional testing
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	testMessage := []byte("test message")
	signature := ed25519.Sign(privateKey, testMessage)
	pubKeyEncoded := base64.StdEncoding.EncodeToString(publicKey)
	sigEncoded := base64.StdEncoding.EncodeToString(signature)

	// Add tests with real keys
	realKeyTests := []struct {
		name      string
		input     string
		expectErr bool
		errType   error
	}{
		{
			name:      "real ed25519 signature - valid",
			input:     fmt.Sprintf(`{"sjsonl": "doc", "key": "%s", "sig": "%s"}`, pubKeyEncoded, sigEncoded),
			expectErr: false,
		},
		{
			name:      "real ed25519 key with invalid signature length",
			input:     fmt.Sprintf(`{"sjsonl": "doc", "key": "%s", "sig": "abcd"}`, pubKeyEncoded),
			expectErr: true,
			errType:   ErrBadSigFormat,
		},
		{
			name:      "invalid key length with real signature",
			input:     fmt.Sprintf(`{"sjsonl": "doc", "key": "abcd", "sig": "%s"}`, sigEncoded),
			expectErr: true,
			errType:   ErrBadKeyFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseControlLine(tt.input)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("Expected error %v, got %v", tt.errType, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("Expected control result but got nil")
				return
			}

			if result.ctlType != tt.ctlType {
				t.Errorf("Expected control type %d, got %d", tt.ctlType, result.ctlType)
			}

			if result.signature == nil {
				t.Error("Expected sig to be populated but got nil")
			}
		})
	}

	for _, tt := range realKeyTests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseControlLine([]byte(tt.input))

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("Expected error %v, got %v", tt.errType, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("Expected control result but got nil")
				return
			}

			if result.ctlType != sign {
				t.Errorf("Expected control type %d, got %d", sign, result.ctlType)
			}

			if result.signature == nil {
				t.Error("Expected sig to be populated but got nil")
				return
			}

			// Verify that the signature internal data was properly extracted
			if !bytes.Equal(result.publicKey, publicKey) {
				t.Error("Public key doesn't match")
			}

			if !bytes.Equal(result.signature, signature) {
				t.Error("Signature doesn't match")
			}
		})
	}
}

func TestCleanAndValidate(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		expected  []byte
		expectErr bool
		errType   error
	}{
		{
			name:     "valid JSON object",
			input:    []byte(`{"key": "value"}`),
			expected: []byte(`{"key": "value"}`),
		},
		{
			name:     "valid JSON object with whitespace",
			input:    []byte(`  {"key": "value"}  `),
			expected: []byte(`{"key": "value"}`),
		},
		{
			name:     "valid JSON object with tabs and newlines",
			input:    []byte("\t\n  {\"key\": \"value\"}  \n\t"),
			expected: []byte(`{"key": "value"}`),
		},
		{
			name:     "complex valid JSON object",
			input:    []byte(`{"name": "test", "number": 42, "array": [1, 2, 3]}`),
			expected: []byte(`{"name": "test", "number": 42, "array": [1, 2, 3]}`),
		},
		{
			name:      "invalid JSON",
			input:     []byte(`{key: "value"}`),
			expectErr: true,
			errType:   ErrInvalidJSON,
		},
		{
			name:      "malformed JSON object",
			input:     []byte(`{"key": "value"`),
			expectErr: true,
			errType:   ErrInvalidJSON,
		},
		{
			name:     "empty JSON object",
			input:    []byte(`{}`),
			expected: []byte(`{}`),
		},
		{
			name:      "empty input",
			input:     []byte(``),
			expectErr: true,
			errType:   ErrEmptyLine,
		},
		{
			name:      "whitespace only",
			input:     []byte(`   `),
			expectErr: true,
			errType:   ErrEmptyLine,
		},
		{
			name:      "starts with non-brace",
			input:     []byte(`x{"key": "value"}`),
			expectErr: true,
			errType:   ErrInvalidJSON,
		},
		{
			name: "multi-line JSON with newline",
			input: []byte(`{"key": "value",
"another": "value"}`),
			expectErr: true,
			errType:   ErrMultiLine,
		},
		{
			name:      "multi-line JSON with carriage return",
			input:     []byte("{\r\"key\": \"value\"}"),
			expectErr: true,
			errType:   ErrMultiLine,
		},
		{
			name:      "multi-line JSON with CRLF",
			input:     []byte("{\"key\": \"value\",\r\n\"another\": \"value\"}"),
			expectErr: true,
			errType:   ErrMultiLine,
		},
		{
			name:      "JSON with embedded newline in string",
			input:     []byte("{\"message\": \"line1\nline2\"}"),
			expectErr: true,
			errType:   ErrMultiLine,
		},
		{
			name:     "JSON with properly escaped newline in string",
			input:    []byte(`{"message": "line1\nline2"}`),
			expected: []byte(`{"message": "line1\nline2"}`),
		},
		{
			name:     "signature line - should pass basic validation",
			input:    fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "%s"}`, b64(0x6b, 32), b64(0x73, 64)),
			expected: fmt.Appendf(nil, `{"sjsonl": "doc", "key": "%s", "sig": "%s"}`, b64(0x6b, 32), b64(0x73, 64)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cleanAndValidate(tt.input)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("Expected error %v, got %v", tt.errType, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if !bytes.Equal(result, tt.expected) {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestLineParseCore(t *testing.T) {
	// Generate real ed25519 keys for testing
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create test data with signature
	testData := []byte(`{"type":"data","value":"test1"}
{"type":"data","value":"test2"}`)

	signedJSONL, err := New(testData, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	signedData := signedJSONL.JSON()

	// Split into lines for testing
	lines := bytes.Split(signedData, []byte("\n"))
	var cleanLines [][]byte
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			cleanLines = append(cleanLines, line)
		}
	}

	tests := []struct {
		name      string
		lines     [][]byte
		mode      int
		expectErr bool
	}{
		{
			name:      "parse mode with valid signature",
			lines:     cleanLines,
			mode:      parse,
			expectErr: false,
		},
		{
			name:      "parse mode with invalid signature key length",
			lines:     [][]byte{fmt.Appendf(nil, `{"sjsonl": "doc", "key": "abcd", "sig": "%s"}`, b64(0x73, 64))},
			mode:      parse,
			expectErr: true,
		},
		{
			name:      "sign mode with valid data",
			lines:     [][]byte{[]byte(`{"type":"data","value":"test"}`)},
			mode:      sign,
			expectErr: false,
		},
		{
			name:      "duplicate line",
			mode:      sign,
			lines:     [][]byte{[]byte(`{"a":1}`), []byte(`{"b":2}`), []byte(`{"a":1}`)},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := linesParseCore(tt.lines, privateKey, tt.mode)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("Expected result but got nil")
				return
			}

			// Verify public key matches
			if !bytes.Equal(result.ctl.publicKey, publicKey) {
				t.Error("Public key doesn't match")
			}

			// For sign mode, verify signature is present
			if tt.mode == sign && len(result.ctl.signature) == 0 {
				t.Error("Expected signature to be generated in sign mode")
			}

			// Verify lines are sorted
			for i := 1; i < len(result.lines); i++ {
				if strings.Compare(result.lines[i-1].hash, result.lines[i].hash) > 0 {
					t.Error("Lines are not sorted by hash")
					break
				}
			}
		})
	}
}

func TestE2E(t *testing.T) {
	require := require.New(t)

	line := `{"type": "data", "value": "test"}`

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err)

	jsonl, err := New([]byte(line), privateKey)
	require.NoError(err)

	out := jsonl.JSON()
	require.NoError(os.WriteFile("/tmp/test.jsonl", out, 0644))

	j2, err := Parse(out)
	require.NoError(err)
	require.Equal(line, string(bytes.Split(j2.JSON(), []byte("\n"))[1]))

	// Perturb data and verify we fail verification
	out[len(out)-5] = 'h'
	_, err = Parse(out)
	require.ErrorIs(err, ErrSigVerificationFailed)
}

func TestEmptyInput(t *testing.T) {
	require := require.New(t)

	// Empty and newline-only input must error, not panic.
	for _, input := range [][]byte{nil, {}, []byte("\n")} {
		_, err := Parse(input)
		require.Error(err)

		_, err = New(input, testKey())
		require.Error(err)
	}
}

func TestDuplicateLineError(t *testing.T) {
	require := require.New(t)

	// Signing: line numbers are 1-based file lines
	_, err := New([]byte(`{"a":1}
{"b":2}
{"a":1}`), testKey())
	require.ErrorIs(err, ErrDuplicateLine)
	require.ErrorContains(err, "line 3")
	require.ErrorContains(err, "first seen at line 1")
	require.ErrorContains(err, `{"a":1}`)

	// Parsing: line numbers account for the header line
	signed, err := New([]byte(`{"a":1}
{"b":2}`), testKey())
	require.NoError(err)

	corrupted := append(signed.JSON(), []byte("{\"a\":1}\n")...)
	_, err = Parse(corrupted)
	require.ErrorIs(err, ErrDuplicateLine)
	require.ErrorContains(err, "line 4")
	require.ErrorContains(err, "first seen at line")
}

func TestParseRm(t *testing.T) {
	require := require.New(t)

	validCases := []string{
		`["abc123"]`,
		`["abc123","def456","789fed"]`,
		`["abcdef0123456789"]`,
		`["1234567890"]`,
		`["a","bb","ccc","dddd"]`,
		`["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35"]`,
		`[]`,
		`[""]`,
		`["","abc123"]`,
	}

	for _, input := range validCases {
		result, err := parseRm(gjson.Parse(input))
		require.NoError(err)
		require.NotNil(result)
	}

	errorCases := []string{
		`"abc123"`,
		`123`,
		`{"a":"b"}`,
		`[123]`,
		`[null]`,
		`[["abc"]]`,
		`["ABC123"]`,
		`["abc-123"]`,
		`["abc 123"]`,
		`["abc.123"]`,
		`["abc_123"]`,
		`["abc/123"]`,
		`["abc+123"]`,
		`["abc=123"]`,
		`["abc123","def@456"]`,
		`["abc123efg456"]`,
		`["abc123,def456"]`,
	}

	for _, input := range errorCases {
		_, err := parseRm(gjson.Parse(input))
		require.ErrorIs(err, ErrRmFormatError)
	}
}

func testKey() ed25519.PrivateKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		panic(err)
	}

	return privateKey
}

func TestParseUnsignedPatchControlLine(t *testing.T) {
	base := strings.Repeat("ba", 32)
	target := strings.Repeat("7a", 32)

	ctl, err := parseControlLine(fmt.Appendf(nil, `{"sjsonl": "patch", "version": "0.1", "base": "%s", "target": "%s", "rm": ["ab"]}`, base, target))
	require.NoError(t, err)
	require.Equal(t, patch, ctl.ctlType)
	require.Nil(t, ctl.publicKey)
	require.Nil(t, ctl.signature)
	require.Equal(t, base, ctl.base)
	require.Equal(t, target, ctl.target)
	require.Equal(t, []string{"ab"}, ctl.rm)

	// Re-serializing omits key and sig rather than emitting empty strings.
	out := ctl.JSON()
	require.NotContains(t, out, `"key"`)
	require.NotContains(t, out, `"sig"`)
}

// setTrailingBits returns s with the unused low bits of its last data
// character set, producing a non-canonical encoding of the same bytes.
func setTrailingBits(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := len(strings.TrimRight(s, "=")) - 1
	return s[:i] + string(alphabet[strings.IndexByte(alphabet, s[i])|1]) + s[i+1:]
}

// b64 returns the standard base64 encoding of n copies of byte c.
func b64(c byte, n int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{c}, n))
}
