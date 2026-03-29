package yara

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"

	"procir/internal/i18n"
)

// Rule represents a parsed YARA rule.
type Rule struct {
	Name      string
	Tags      []string
	Meta      map[string]string
	Strings   []*StringDef
	Condition string // raw condition text
}

// StringDef represents a string definition within a YARA rule.
type StringDef struct {
	ID        string // e.g. "$s1"
	Value     []byte // compiled pattern bytes
	IsHex     bool
	IsRegex   bool
	Regex     *regexp.Regexp
	NoCase    bool
	Wide      bool
	ASCII     bool
	Fullword  bool
	Alternates [][]byte // for hex patterns with wildcards, we expand to multiple checks
	HasWild   bool      // contains ?? wildcards
	WildMask  []byte    // mask for wildcard matching (0xFF = match, 0x00 = wildcard)
}

// RuleSet holds all compiled rules.
type RuleSet struct {
	Rules    []*Rule
	Hash     string // hash of source files for cache invalidation
	Errors   []string
}

// LoadRules loads YARA rules from a file or directory.
func LoadRules(path string) (*RuleSet, error) {
	rs := &RuleSet{
		Hash: path,
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf(i18n.T("yara_path_not_exist")+": %s", path)
	}

	if info.IsDir() {
		// Load all .yar / .yara files in directory
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext == ".yar" || ext == ".yara" || ext == ".rule" {
				data, err := os.ReadFile(filepath.Join(path, entry.Name()))
				if err != nil {
					rs.Errors = append(rs.Errors, fmt.Sprintf(i18n.T("yara_read_fail")+" %s: %v", entry.Name(), err))
					continue
				}
				rules, errs := parseRules(string(data))
				rs.Rules = append(rs.Rules, rules...)
				rs.Errors = append(rs.Errors, errs...)
			}
		}
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rules, errs := parseRules(string(data))
		rs.Rules = rules
		rs.Errors = errs
	}

	if len(rs.Rules) == 0 && len(rs.Errors) > 0 {
		return rs, fmt.Errorf(i18n.T("yara_no_valid_rules")+": %s", strings.Join(rs.Errors, "; "))
	}

	return rs, nil
}

// parseRules parses YARA source text into Rule objects.
func parseRules(source string) ([]*Rule, []string) {
	var rules []*Rule
	var errors []string

	// Remove C-style comments
	source = removeCComments(source)

	// Split into individual rules
	remaining := source
	for {
		remaining = strings.TrimSpace(remaining)
		if remaining == "" {
			break
		}

		// Find "rule <name>" or "private rule <name>" or "global rule <name>"
		idx := findRuleStart(remaining)
		if idx < 0 {
			break
		}
		remaining = remaining[idx:]

		// Find matching closing brace
		rule, rest, err := extractRule(remaining)
		if err != nil {
			errors = append(errors, err.Error())
			// Try to skip past this rule
			if braceIdx := strings.Index(remaining[1:], "\nrule "); braceIdx >= 0 {
				remaining = remaining[braceIdx+1:]
			} else {
				break
			}
			continue
		}

		if rule != nil {
			rules = append(rules, rule)
		}
		remaining = rest
	}

	return rules, errors
}

func findRuleStart(s string) int {
	patterns := []string{"rule ", "private rule ", "global rule "}
	minIdx := -1
	for _, p := range patterns {
		idx := strings.Index(s, p)
		if idx >= 0 && (minIdx < 0 || idx < minIdx) {
			minIdx = idx
		}
	}
	return minIdx
}

func extractRule(source string) (*Rule, string, error) {
	// Find rule name
	start := strings.Index(source, "rule ")
	if start < 0 {
		return nil, source, fmt.Errorf("%s", i18n.T("yara_no_rule_keyword"))
	}

	afterRule := source[start+5:]
	// Skip "private " / "global " prefix that may have been consumed
	afterRule = strings.TrimSpace(afterRule)

	// Get rule name (up to : or {)
	nameEnd := strings.IndexAny(afterRule, ":{")
	if nameEnd < 0 {
		return nil, source, fmt.Errorf("%s", i18n.T("yara_syntax_error_brace"))
	}

	rule := &Rule{
		Name: strings.TrimSpace(afterRule[:nameEnd]),
		Meta: make(map[string]string),
	}

	rest := afterRule[nameEnd:]

	// Parse tags (between name and {)
	if rest[0] == ':' {
		tagEnd := strings.Index(rest, "{")
		if tagEnd < 0 {
			return nil, source, fmt.Errorf(i18n.T("yara_rule_missing_open")+" %s", rule.Name)
		}
		tagStr := strings.TrimSpace(rest[1:tagEnd])
		for _, tag := range strings.Fields(tagStr) {
			rule.Tags = append(rule.Tags, tag)
		}
		rest = rest[tagEnd:]
	}

	// Find matching closing brace
	braceCount := 0
	endIdx := -1
	for i, c := range rest {
		if c == '{' {
			braceCount++
		} else if c == '}' {
			braceCount--
			if braceCount == 0 {
				endIdx = i
				break
			}
		}
	}

	if endIdx < 0 {
		return nil, "", fmt.Errorf(i18n.T("yara_rule_missing_close")+" %s", rule.Name)
	}

	body := rest[1:endIdx] // content between { and }
	remaining := rest[endIdx+1:]

	// Parse sections: meta, strings, condition
	parseMeta(body, rule)
	parseStrings(body, rule)
	parseCondition(body, rule)

	return rule, remaining, nil
}

func parseMeta(body string, rule *Rule) {
	section := extractSection(body, "meta")
	if section == "" {
		return
	}

	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"`)
		rule.Meta[key] = val
	}
}

func parseStrings(body string, rule *Rule) {
	section := extractSection(body, "strings")
	if section == "" {
		return
	}

	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "$") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		id := strings.TrimSpace(parts[0])
		valPart := strings.TrimSpace(parts[1])

		sd := &StringDef{
			ID:    id,
			ASCII: true,
		}

		if strings.HasPrefix(valPart, "{") {
			// Hex string
			endBrace := strings.Index(valPart, "}")
			if endBrace < 0 {
				continue
			}
			hexStr := strings.TrimSpace(valPart[1:endBrace])
			sd.IsHex = true
			parseHexPattern(hexStr, sd)
			// Parse modifiers after }
			modifiers := valPart[endBrace+1:]
			parseModifiers(modifiers, sd)
		} else if strings.HasPrefix(valPart, "/") {
			// Regex
			endSlash := strings.LastIndex(valPart, "/")
			if endSlash <= 0 {
				continue
			}
			pattern := valPart[1:endSlash]
			modifiers := valPart[endSlash+1:]

			flags := ""
			if strings.Contains(modifiers, "i") || strings.Contains(strings.ToLower(modifiers), "nocase") {
				flags = "(?i)"
			}

			re, err := regexp.Compile(flags + pattern)
			if err == nil {
				sd.IsRegex = true
				sd.Regex = re
			}
			parseModifiers(modifiers, sd)
		} else if strings.HasPrefix(valPart, `"`) {
			// Text string
			// Find closing quote (handle escaped quotes)
			text := extractQuotedString(valPart)
			sd.Value = []byte(text)

			// Parse modifiers after the quoted string
			afterQuote := valPart[strings.LastIndex(valPart, `"`)+1:]
			parseModifiers(afterQuote, sd)

			// If wide, create UTF-16LE version
			if sd.Wide {
				sd.Value = toUTF16LE(text)
			}
			if sd.NoCase && !sd.Wide {
				sd.Value = []byte(strings.ToLower(text))
			}
		}

		rule.Strings = append(rule.Strings, sd)
	}
}

func parseCondition(body string, rule *Rule) {
	section := extractSection(body, "condition")
	if section == "" {
		rule.Condition = "any of them"
		return
	}
	rule.Condition = strings.TrimSpace(section)
}

func extractSection(body, name string) string {
	marker := name + ":"
	idx := strings.Index(body, marker)
	if idx < 0 {
		return ""
	}

	start := idx + len(marker)

	// Find next section or end
	sections := []string{"meta:", "strings:", "condition:"}
	endIdx := len(body)
	for _, s := range sections {
		if s == marker {
			continue
		}
		si := strings.Index(body[start:], s)
		if si >= 0 && start+si < endIdx {
			endIdx = start + si
		}
	}

	return body[start:endIdx]
}

func parseHexPattern(hexStr string, sd *StringDef) {
	hexStr = strings.ReplaceAll(hexStr, "\n", " ")
	hexStr = strings.ReplaceAll(hexStr, "\r", " ")
	tokens := strings.Fields(hexStr)

	var pattern []byte
	var mask []byte
	hasWild := false

	for _, token := range tokens {
		if token == "??" || token == "?" {
			pattern = append(pattern, 0x00)
			mask = append(mask, 0x00)
			hasWild = true
		} else if len(token) == 2 {
			b, err := hex.DecodeString(token)
			if err == nil {
				pattern = append(pattern, b[0])
				mask = append(mask, 0xFF)
			}
		}
		// Skip alternation groups (|), jumps [N-M] for simplicity
	}

	sd.Value = pattern
	sd.WildMask = mask
	sd.HasWild = hasWild
}

func parseModifiers(modStr string, sd *StringDef) {
	lower := strings.ToLower(modStr)
	if strings.Contains(lower, "nocase") {
		sd.NoCase = true
	}
	if strings.Contains(lower, "wide") {
		sd.Wide = true
	}
	if strings.Contains(lower, "ascii") {
		sd.ASCII = true
	}
	if strings.Contains(lower, "fullword") {
		sd.Fullword = true
	}
}

func extractQuotedString(s string) string {
	if !strings.HasPrefix(s, `"`) {
		return ""
	}
	var result []byte
	escaped := false
	for i := 1; i < len(s); i++ {
		if escaped {
			switch s[i] {
			case 'n':
				result = append(result, '\n')
			case 'r':
				result = append(result, '\r')
			case 't':
				result = append(result, '\t')
			case '\\':
				result = append(result, '\\')
			case '"':
				result = append(result, '"')
			default:
				result = append(result, '\\', s[i])
			}
			escaped = false
		} else if s[i] == '\\' {
			escaped = true
		} else if s[i] == '"' {
			break
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}

func toUTF16LE(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	result := make([]byte, len(encoded)*2)
	for i, v := range encoded {
		result[i*2] = byte(v)
		result[i*2+1] = byte(v >> 8)
	}
	return result
}

func removeCComments(s string) string {
	// Remove /* ... */ comments
	for {
		start := strings.Index(s, "/*")
		if start < 0 {
			break
		}
		end := strings.Index(s[start:], "*/")
		if end < 0 {
			break
		}
		s = s[:start] + s[start+end+2:]
	}
	// Remove // comments
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "//"); idx >= 0 {
			// Make sure it's not inside a string
			if !isInsideString(line, idx) {
				lines[i] = line[:idx]
			}
		}
	}
	return strings.Join(lines, "\n")
}

func isInsideString(line string, pos int) bool {
	inStr := false
	for i := 0; i < pos; i++ {
		if line[i] == '"' && (i == 0 || line[i-1] != '\\') {
			inStr = !inStr
		}
	}
	return inStr
}
