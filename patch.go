package sjsonl

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/samber/lo"
)

func (src *JSONL) Patch(patch *JSONL) (*JSONL, error) {
	// The patch must have been generated against this exact document.
	if srcHash := src.hash(); srcHash != patch.ctl.base {
		return nil, fmt.Errorf("%w: base %s, document %s", ErrBaseMismatch, patch.ctl.base, srcHash)
	}

	// Remove lines from src
	newLineSet := make([]hashedLine, 0, len(src.lines))

outer:
	for _, line := range src.lines {
		for _, prefix := range patch.ctl.rm {
			if strings.HasPrefix(line.hash, prefix) {
				continue outer
			}
		}
		newLineSet = append(newLineSet, line)
	}

	// Add new lines
	for _, line := range patch.lines {
		newLineSet = append(newLineSet, line)
	}

	slices.SortFunc(newLineSet, func(a, b hashedLine) int {
		return strings.Compare(a.hash, b.hash)
	})

	// A patch may not add a line already present in the base (duplicates
	// within the patch itself are caught when the patch is parsed).
	for i := 1; i < len(newLineSet); i++ {
		if newLineSet[i].hash == newLineSet[i-1].hash {
			return nil, fmt.Errorf("patch adds line already in base: %w: %s",
				ErrDuplicateLine, snippet(newLineSet[i].line))
		}
	}

	jsonl := JSONL{
		lines: newLineSet,
		ctl: controlLine{
			ctlType:   sign,
			publicKey: patch.ctl.publicKey,
			signature: patch.ctl.signature,
		},
	}

	if patch.ctl.publicKey == nil {
		jsonl.ctl.ctlType = unsigned
	}

	jsonl.info = newInfo(&jsonl)

	if jsonl.info.Hash != patch.ctl.target {
		return nil, fmt.Errorf("%w: target %s, patched %s", ErrTargetMismatch, patch.ctl.target, jsonl.info.Hash)
	}

	if jsonl.ctl.ctlType == sign {
		msg := concatLineHashes(newLineSet)
		if !ed25519.Verify(jsonl.ctl.publicKey, msg, jsonl.ctl.signature) {
			return nil, ErrSigVerificationFailed
		}
	}

	return &jsonl, nil
}

func (src *JSONL) Diff(tgt *JSONL) (*JSONL, error) {
	deletions, additions := difference(src.lines, tgt.lines)

	deletedHashes := lo.Map(deletions, func(line hashedLine, _ int) string {
		return line.hash
	})

	srcHashes := lo.Map(src.lines, func(line hashedLine, _ int) string {
		return line.hash
	})

	slog.Debug("srcHashes", "hashes", trunc(srcHashes))
	slog.Debug("deletedHashes", "hashes", trunc(deletedHashes))

	deletedHashes = findUniquePrefixes(deletedHashes, srcHashes)

	out := &JSONL{
		lines: additions,
		ctl: controlLine{
			ctlType:   patch,
			publicKey: tgt.ctl.publicKey,
			signature: tgt.ctl.signature,
			base:      src.hash(),
			target:    tgt.hash(),
			rm:        deletedHashes,
		},
	}

	return out, nil
}

// findUniquePrefixes returns the unique prefixes for target strings that distinguish them from all strings.
// Assumes targets is a subset of all.
func findUniquePrefixes(targets, all []string) []string {
	if len(targets) == 0 {
		return []string{}
	}

	targetMap := lo.Keyify(targets)

	// Build a set of non-target strings for efficient lookup
	nonTargets := make(map[string]struct{})
	for _, str := range all {
		if _, isTarget := targetMap[str]; !isTarget {
			nonTargets[str] = struct{}{}
		}
	}

	// For each target, find the shortest prefix that doesn't match any non-target
	prefixMap := make(map[string]struct{})
	for _, target := range targets {
		// Handle empty string target
		if len(target) == 0 {
			prefixMap[""] = struct{}{}
			continue
		}

		foundPrefix := false
		// Try progressively longer prefixes
		for prefixLen := 1; prefixLen <= len(target); prefixLen++ {
			prefix := target[:prefixLen]

			// Check if this prefix matches any non-target
			matchesNonTarget := false
			for nonTarget := range nonTargets {
				if strings.HasPrefix(nonTarget, prefix) {
					matchesNonTarget = true
					break
				}
			}

			// If this prefix doesn't match any non-target, use it
			if !matchesNonTarget {
				prefixMap[prefix] = struct{}{}
				foundPrefix = true
				break
			}
		}

		// If no shorter prefix works, use the full target string
		if !foundPrefix {
			prefixMap[target] = struct{}{}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(prefixMap))
	for prefix := range prefixMap {
		result = append(result, prefix)
	}

	// Sort for consistent output
	sort.Strings(result)

	return result
}

// commonPrefixLen returns the length of the longest common prefix of two strings.
// It is only guaranteed to be correct for bytes, but that's OK for our hex hashes.
func commonPrefixLen(s1, s2 string) int {
	minLen := min(len(s1), len(s2))
	for i := range minLen {
		if s1[i] != s2[i] {
			return i
		}
	}

	return minLen
}

// Difference returns the difference between two collections.
// The first value is the collection of element absent of list2.
// The second value is the collection of element absent of list1.
// Modified from lo.Difference
func difference(list1, list2 []hashedLine) ([]hashedLine, []hashedLine) {
	var left []hashedLine
	var right []hashedLine

	maxLen := max(len(list1), len(list2))
	seenLeft := make(map[string]struct{}, maxLen)
	seenRight := make(map[string]struct{}, maxLen)

	for i := range list1 {
		seenLeft[string(list1[i].hash)] = struct{}{}
	}

	for i := range list2 {
		seenRight[string(list2[i].hash)] = struct{}{}
	}

	for i := range list1 {
		if _, ok := seenRight[string(list1[i].hash)]; !ok {
			left = append(left, list1[i])
		}
	}

	for i := range list2 {
		if _, ok := seenLeft[string(list2[i].hash)]; !ok {
			right = append(right, list2[i])
		}
	}

	return left, right
}

func trunc(ss []string) []string {
	return lo.Map(ss, func(s string, _ int) string {
		return s[:min(len(s), 7)]
	})
}
