package indicator

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"procir/internal/i18n"
	"procir/internal/types"
)

var (
	reURL  = regexp.MustCompile(`https?://[^\s"'<>\x60\x00-\x1f]{5,200}`)
	reIPv4 = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
)

// Extract scans all text sources and returns IOCs.
func Extract(
	processes []*types.ProcessRecord,
	triggers []*types.TriggerEntry,
	forensics []*types.ForensicEntry,
) []*types.Indicator {
	seen := make(map[string]bool)
	var results []*types.Indicator

	add := func(iocType, value, source, context string) {
		key := iocType + ":" + value
		if seen[key] {
			return
		}
		seen[key] = true
		results = append(results, &types.Indicator{
			Type:         iocType,
			Value:        value,
			SourceObject: source,
			Context:      context,
		})
	}

	// Scan processes: network IPs + command lines in a single pass
	for _, p := range processes {
		source := p.Name + " (PID:" + strconv.Itoa(int(p.PID)) + ")"
		for _, ip := range p.RemoteIPs {
			if isPublicIPStr(ip) {
				add("ip", ip, source, i18n.T("ioc_network_conn"))
			}
		}
		if p.CommandLine != "" {
			extractFromText(p.CommandLine, source, i18n.T("ioc_proc_cmdline"), add)
		}
	}

	// Scan triggers
	for _, t := range triggers {
		if t.CommandLine == "" && t.WMIConsumerCmd == "" {
			continue
		}
		source := string(t.Type) + ":" + t.Name
		if t.CommandLine != "" {
			extractFromText(t.CommandLine, source, i18n.T("ioc_trigger"), add)
		}
		if t.WMIConsumerCmd != "" {
			extractFromText(t.WMIConsumerCmd, source, "WMI Consumer", add)
		}
	}

	// Scan forensic entries
	for _, f := range forensics {
		if f.CommandLine == "" {
			continue
		}
		source := string(f.Source) + ":" + filepath.Base(f.Path)
		extractFromText(f.CommandLine, source, i18n.T("ioc_forensic"), add)
	}

	return results
}

func extractFromText(text, source, context string, add func(string, string, string, string)) {
	for _, url := range reURL.FindAllString(text, -1) {
		add("url", url, source, context)
	}

	for _, match := range reIPv4.FindAllStringSubmatch(text, -1) {
		if len(match) < 5 {
			continue
		}
		ip := match[0]
		if isValidPublicIP(parseOctet(match[1]), parseOctet(match[2]), parseOctet(match[3]), parseOctet(match[4])) {
			add("ip", ip, source, context)
		}
	}
}

// isPublicIPStr validates and checks a dotted-quad string.
func isPublicIPStr(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	return isValidPublicIP(parseOctet(parts[0]), parseOctet(parts[1]), parseOctet(parts[2]), parseOctet(parts[3]))
}

// isValidPublicIP checks parsed octets against private/reserved ranges.
func isValidPublicIP(o1, o2, o3, o4 int) bool {
	if o1 < 0 || o2 < 0 || o3 < 0 || o4 < 0 {
		return false
	}
	if o1 == 0 || o1 == 127 || o1 == 255 {
		return false
	}
	if o1 == 10 {
		return false
	}
	if o1 == 192 && o2 == 168 {
		return false
	}
	if o1 == 172 && o2 >= 16 && o2 <= 31 {
		return false
	}
	if o1 == 169 && o2 == 254 {
		return false
	}
	if o1 >= 224 && o1 <= 239 {
		return false
	}
	return true
}

func parseOctet(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 255 {
		return -1
	}
	return n
}

