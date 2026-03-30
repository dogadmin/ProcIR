package yara

import (
	"bytes"
	"os"
	"strconv"
	"strings"
)

const maxFileSize = 100 * 1024 * 1024 // 100MB

// ScanFile scans a single file against the ruleset and returns matches.
func ScanFile(path string, rs *RuleSet) []YaraHit {
	if rs == nil || len(rs.Rules) == 0 {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() == 0 || info.Size() > maxFileSize {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	return ScanData(data, path, rs)
}

// ScanData scans byte data against the ruleset.
func ScanData(data []byte, targetPath string, rs *RuleSet) []YaraHit {
	var hits []YaraHit

	dataLower := bytes.ToLower(data) // pre-compute for nocase matching

	for _, rule := range rs.Rules {
		matched, matchedStrings := evaluateRule(rule, data, dataLower)
		if matched {
			hit := YaraHit{
				RuleName:   rule.Name,
				Tags:       rule.Tags,
				Meta:       rule.Meta,
				Strings:    matchedStrings,
				TargetPath: targetPath,
			}
			if ns, ok := rule.Meta["namespace"]; ok {
				hit.Namespace = ns
			}
			hits = append(hits, hit)
		}
	}

	return hits
}

// evaluateRule checks if a rule matches the given data.
func evaluateRule(rule *Rule, data, dataLower []byte) (bool, []string) {
	if len(rule.Strings) == 0 {
		// No strings section — condition-only rule (e.g. filesize checks)
		return evaluateConditionOnly(rule, data), nil
	}

	// Match each string definition
	stringMatches := make(map[string]bool)
	var matchedNames []string

	for _, sd := range rule.Strings {
		if matchString(sd, data, dataLower) {
			stringMatches[sd.ID] = true
			matchedNames = append(matchedNames, sd.ID)
		}
	}

	// Evaluate condition
	condMet := evaluateCondition(rule.Condition, stringMatches, len(rule.Strings), data)

	if condMet {
		return true, matchedNames
	}
	return false, nil
}

// matchString checks if a string definition matches anywhere in the data.
func matchString(sd *StringDef, data, dataLower []byte) bool {
	if sd.IsRegex && sd.Regex != nil {
		return sd.Regex.Match(data)
	}

	if len(sd.Value) == 0 {
		return false
	}

	if sd.IsHex && sd.HasWild {
		return matchHexWildcard(sd.Value, sd.WildMask, data)
	}

	searchIn := data
	searchFor := sd.Value

	if sd.NoCase && !sd.Wide {
		searchIn = dataLower
		searchFor = []byte(strings.ToLower(string(sd.Value)))
	}

	if sd.Fullword {
		return matchFullword(searchFor, searchIn)
	}

	return bytes.Contains(searchIn, searchFor)
}

// matchHexWildcard matches a hex pattern with ?? wildcards.
func matchHexWildcard(pattern, mask, data []byte) bool {
	patLen := len(pattern)
	if patLen == 0 || len(data) < patLen {
		return false
	}

	for i := 0; i <= len(data)-patLen; i++ {
		matched := true
		for j := 0; j < patLen; j++ {
			if mask[j] != 0 && data[i+j] != pattern[j] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// matchFullword ensures the pattern is bounded by non-alphanumeric chars.
func matchFullword(pattern, data []byte) bool {
	patLen := len(pattern)
	for i := 0; i <= len(data)-patLen; i++ {
		if !bytes.Equal(data[i:i+patLen], pattern) {
			continue
		}
		// Check boundaries
		if i > 0 && isAlphanumeric(data[i-1]) {
			continue
		}
		if i+patLen < len(data) && isAlphanumeric(data[i+patLen]) {
			continue
		}
		return true
	}
	return false
}

func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// evaluateCondition parses and evaluates the condition string.
func evaluateCondition(cond string, matches map[string]bool, totalStrings int, data []byte) bool {
	cond = strings.TrimSpace(cond)

	// Common patterns
	switch {
	case cond == "any of them":
		return len(matches) > 0

	case cond == "all of them":
		return len(matches) == totalStrings

	case strings.HasPrefix(cond, "any of ($"):
		// any of ($s*)
		prefix := extractWildcardPrefix(cond)
		for id := range matches {
			if strings.HasPrefix(id, prefix) {
				return true
			}
		}
		return false

	case strings.HasPrefix(cond, "all of ($"):
		prefix := extractWildcardPrefix(cond)
		count := 0
		total := 0
		for id := range matches {
			if strings.HasPrefix(id, prefix) {
				count++
			}
		}
		_ = total
		return count > 0 && count == countWithPrefix(matches, prefix, totalStrings)

	case isNofThem(cond):
		// "N of them" or "N of ($s*)"
		n := extractN(cond)
		return len(matches) >= n
	}

	// Try to evaluate as boolean expression of string IDs
	return evaluateBoolExpr(cond, matches, data)
}

// evaluateBoolExpr handles simple boolean expressions like "$s1 and $s2" or "$s1 or $s2"
func evaluateBoolExpr(cond string, matches map[string]bool, data []byte) bool {
	cond = strings.TrimSpace(cond)

	// Handle parentheses (simplified - strip outer)
	if strings.HasPrefix(cond, "(") && strings.HasSuffix(cond, ")") {
		cond = cond[1 : len(cond)-1]
	}

	// Split by " or " first (lower precedence)
	if parts := splitOutsideParens(cond, " or "); len(parts) > 1 {
		for _, part := range parts {
			if evaluateBoolExpr(part, matches, data) {
				return true
			}
		}
		return false
	}

	// Split by " and "
	if parts := splitOutsideParens(cond, " and "); len(parts) > 1 {
		for _, part := range parts {
			if !evaluateBoolExpr(part, matches, data) {
				return false
			}
		}
		return true
	}

	// Handle "not"
	if strings.HasPrefix(cond, "not ") {
		return !evaluateBoolExpr(cond[4:], matches, data)
	}

	// Single string reference: $s1
	cond = strings.TrimSpace(cond)
	if strings.HasPrefix(cond, "$") {
		return matches[cond]
	}

	// filesize check (simplified)
	if strings.Contains(cond, "filesize") {
		return evaluateFilesize(cond, len(data))
	}

	// Default: if we can't parse it, check if any strings matched
	return len(matches) > 0
}

func evaluateConditionOnly(rule *Rule, data []byte) bool {
	cond := strings.TrimSpace(rule.Condition)
	if strings.Contains(cond, "filesize") {
		return evaluateFilesize(cond, len(data))
	}
	return false
}

func evaluateFilesize(cond string, size int) bool {
	// Simple: "filesize < 1000" or "filesize > 100KB"
	cond = strings.TrimSpace(cond)
	if strings.Contains(cond, "filesize") {
		parts := strings.Fields(cond)
		for i, p := range parts {
			if p == "filesize" && i+2 < len(parts) {
				op := parts[i+1]
				valStr := parts[i+2]
				val := parseSize(valStr)
				switch op {
				case "<":
					return size < val
				case ">":
					return size > val
				case "<=":
					return size <= val
				case ">=":
					return size >= val
				case "==":
					return size == val
				}
			}
		}
	}
	return false
}

func parseSize(s string) int {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return 0
	}
	multiplier := 1
	if len(s) > 2 && strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = s[:len(s)-2]
	} else if len(s) > 2 && strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = s[:len(s)-2]
	}
	n, _ := strconv.Atoi(s)
	return n * multiplier
}

func extractWildcardPrefix(cond string) string {
	// "any of ($s*)" → "$s"
	start := strings.Index(cond, "($")
	if start < 0 {
		return "$"
	}
	end := strings.Index(cond[start:], "*")
	if end < 0 {
		return "$"
	}
	return cond[start+1 : start+end]
}

func isNofThem(cond string) bool {
	parts := strings.Fields(cond)
	if len(parts) >= 3 && parts[1] == "of" {
		_, err := strconv.Atoi(parts[0])
		return err == nil
	}
	return false
}

func extractN(cond string) int {
	parts := strings.Fields(cond)
	if len(parts) >= 1 {
		n, _ := strconv.Atoi(parts[0])
		return n
	}
	return 0
}

func countWithPrefix(matches map[string]bool, prefix string, total int) int {
	count := 0
	for id := range matches {
		if strings.HasPrefix(id, prefix) {
			count++
		}
	}
	return count
}

func splitOutsideParens(s, sep string) []string {
	depth := 0
	var parts []string
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '(' {
			depth++
		} else if s[i] == ')' {
			depth--
		} else if depth == 0 && i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			parts = append(parts, s[last:i])
			last = i + len(sep)
			i += len(sep) - 1
		}
	}
	parts = append(parts, s[last:])
	if len(parts) <= 1 {
		return nil // no split occurred
	}
	return parts
}
