package sjsonl

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommonPrefixLen(t *testing.T) {
	tests := []struct {
		name     string
		s1       string
		s2       string
		expected int
	}{
		{
			name:     "identical strings",
			s1:       "hello",
			s2:       "hello",
			expected: 5,
		},
		{
			name:     "one is prefix of another",
			s1:       "hello",
			s2:       "helloworld",
			expected: 5,
		},
		{
			name:     "no common prefix",
			s1:       "abc",
			s2:       "xyz",
			expected: 0,
		},
		{
			name:     "partial common prefix",
			s1:       "hello",
			s2:       "help",
			expected: 3,
		},
		{
			name:     "both empty strings",
			s1:       "",
			s2:       "",
			expected: 0,
		},
		{
			name:     "one empty string",
			s1:       "",
			s2:       "hello",
			expected: 0,
		},
		{
			name:     "other empty string",
			s1:       "hello",
			s2:       "",
			expected: 0,
		},
		{
			name:     "single character match",
			s1:       "a",
			s2:       "ab",
			expected: 1,
		},
		{
			name:     "single character no match",
			s1:       "a",
			s2:       "b",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := commonPrefixLen(tt.s1, tt.s2)
			assert.Equal(t, tt.expected, result, "commonPrefixLen(%q, %q)", tt.s1, tt.s2)
		})
	}
}

func TestFindUniquePrefixes(t *testing.T) {
	tests := []struct {
		name     string
		targets  []string
		all      []string
		expected []string
	}{
		{
			name:     "empty targets",
			targets:  []string{},
			all:      []string{"abc", "def"},
			expected: []string{},
		},
		{
			name:     "single target, no conflicts",
			targets:  []string{"abc"},
			all:      []string{"abc"},
			expected: []string{"a"},
		},
		{
			name:     "targets need distinction from all",
			targets:  []string{"abc", "def"},
			all:      []string{"abc", "def", "ab", "de"},
			expected: []string{"abc", "def"},
		},
		{
			name:     "some common prefixes",
			targets:  []string{"abc", "abd"},
			all:      []string{"abc", "abd", "xyz"},
			expected: []string{"a"},
		},
		{
			name:     "targets conflict with each other",
			targets:  []string{"abc", "abd"},
			all:      []string{"abc", "abd"},
			expected: []string{"a"},
		},
		{
			name:     "prefix relationships",
			targets:  []string{"a", "ab"},
			all:      []string{"a", "ab", "abc"},
			expected: []string{"a", "ab"},
		},
		{
			name: "hex hashes (realistic use case)",
			targets: []string{
				"abcdef123456",
				"xyz123456789",
			},
			all: []string{
				"abcdef123456",
				"xyz123456789",
				"abcd56789012",
				"abcdef654321",
			},
			expected: []string{"abcdef1", "x"}, // sorted order of prefixes
		},
		{
			name:     "empty string in targets",
			targets:  []string{"", "abc"},
			all:      []string{"", "abc"},
			expected: []string{"", "a"},
		},
		{
			name:     "overlapping targets and all",
			targets:  []string{"same", "different"},
			all:      []string{"same", "different", "other"},
			expected: []string{"d", "s"},
		},
		{
			name:     "targets need distinction from larger set",
			targets:  []string{"apple", "application"},
			all:      []string{"apple", "application", "apply", "april", "banana"},
			expected: []string{"apple", "appli"},
		},
		{
			name:     "multiple targets share prefix",
			targets:  []string{"test1", "test2", "test3"},
			all:      []string{"test1", "test2", "test3", "other"},
			expected: []string{"t"},
		},
		{
			name:     "mixed prefix lengths",
			targets:  []string{"aa", "ab", "ba", "bb"},
			all:      []string{"aa", "ab", "ba", "bb", "ca", "cb"},
			expected: []string{"a", "b"},
		},
		{
			name:     "single character distinction",
			targets:  []string{"x"},
			all:      []string{"x", "y", "z"},
			expected: []string{"x"},
		},
		{
			name:     "prefix with non-target in middle",
			targets:  []string{"abc", "abz"},
			all:      []string{"abc", "abd", "abz"},
			expected: []string{"abc", "abz"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findUniquePrefixes(tt.targets, tt.all)
			slices.Sort(result)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPatchAddsDuplicate(t *testing.T) {
	require := require.New(t)

	src, err := New([]byte(`{"a":1}
{"b":2}`), testKey())
	require.NoError(err)

	// A hand-crafted patch that deletes nothing and adds a line already in
	// the base. The key/sig only need to be well-formed; Patch does not
	// verify them.
	patchData := fmt.Sprintf(`{"sjsonl":"patch","version":"0.1","key":"%s","sig":"%s","base":"abcd","target":"beef","rm":[]}
{"a":1}
`, strings.Repeat("6b", 32), strings.Repeat("73", 64))

	p, err := ParsePatch([]byte(patchData))
	require.NoError(err)

	_, err = src.Patch(p)
	require.ErrorIs(err, ErrDuplicateLine)
	require.ErrorContains(err, "already in base")
	require.ErrorContains(err, `{"a":1}`)
}

func TestPatch(t *testing.T) {
	require := require.New(t)

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err)

	srcLines := `{"a":42}
{"b":95}
{"c":96}
{"d":96}
{"e":96}
{"f":96}
{"g":96}
`

	tgtLines := `{"a":42}
	{"b":95}
{"y":98}
{"z":100}
`

	src, err := New([]byte(srcLines), privateKey)
	require.NoError(err)
	require.NoError(os.WriteFile("/tmp/src.json", src.JSON(), 0644))

	tgt, err := New([]byte(tgtLines), privateKey)
	require.NoError(err)
	require.NoError(os.WriteFile("/tmp/tgt.json", tgt.JSON(), 0644))

	out, err := src.Diff(tgt)
	require.NoError(err)
	require.Equal(src.hash(), out.ctl.base)
	require.Equal(tgt.hash(), out.ctl.target)
	require.NoError(os.WriteFile("/tmp/patch.json", out.JSON(), 0644))

	out, err = ParsePatch(out.JSON())
	require.NoError(err)
	require.Equal(src.hash(), out.ctl.base)
	require.Equal(tgt.hash(), out.ctl.target)

	patched, err := src.Patch(out)
	require.NoError(err)
	require.NoError(os.WriteFile("/tmp/patched.json", patched.JSON(), 0644))
	// clean := func(data string) []byte {
	// 	return []byte(strings.TrimSpace(data))
	// }

	// out, err := Diff([]byte(clean(base)), []byte(clean(tgt)))
	// require.NoError(err)

	// require.NoError(os.WriteFile("/tmp/diff.json", out, 0644))

}
