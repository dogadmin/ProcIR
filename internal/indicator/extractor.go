package indicator

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"

	"procir/internal/i18n"
	"procir/internal/types"
)

var (
	reURL    = regexp.MustCompile(`https?://[^\s"'<>\x60\x00-\x1f]{5,200}`)
	reIPv4   = regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}\b`)
	reDomain = regexp.MustCompile(`\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	reBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	rePath   = regexp.MustCompile(`[A-Za-z]:\\[^\s"'<>|:*?]{5,200}`)
)

// Extract scans all text sources and returns IOCs.
func Extract(
	processes []*types.ProcessRecord,
	triggers []*types.TriggerEntry,
	forensics []*types.ForensicEntry,
) []*types.Indicator {
	seen := make(map[string]bool) // dedup by type+value
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

	// Scan process command lines
	for _, p := range processes {
		if p.CommandLine == "" {
			continue
		}
		source := p.Name + " (PID:" + itoa(int(p.PID)) + ")"
		extractFromText(p.CommandLine, source, i18n.T("ioc_proc_cmdline"), add)
	}

	// Scan triggers
	for _, t := range triggers {
		if t.CommandLine == "" {
			continue
		}
		source := string(t.Type) + ":" + t.Name
		extractFromText(t.CommandLine, source, i18n.T("ioc_trigger"), add)

		// WMI-specific
		if t.WMIConsumerCmd != "" {
			extractFromText(t.WMIConsumerCmd, source, "WMI Consumer", add)
		}
	}

	// Scan forensic entries (event logs especially)
	for _, f := range forensics {
		if f.CommandLine == "" {
			continue
		}
		source := string(f.Source) + ":" + baseName(f.Path)
		extractFromText(f.CommandLine, source, i18n.T("ioc_forensic"), add)
	}

	return results
}

func extractFromText(text, source, context string, add func(string, string, string, string)) {
	// URLs
	for _, url := range reURL.FindAllString(text, -1) {
		add("url", url, source, context)
	}

	// IPs (skip private/localhost)
	for _, ip := range reIPv4.FindAllString(text, -1) {
		if isPublicIP(ip) {
			add("ip", ip, source, context)
		}
	}

	// Domains (from URLs or standalone, skip common ones)
	for _, domain := range reDomain.FindAllString(text, -1) {
		dl := strings.ToLower(domain)
		if isInterestingDomain(dl) {
			add("domain", dl, source, context)
		}
	}

	// Base64 blobs
	for _, b64 := range reBase64.FindAllString(text, -1) {
		if isLikelyBase64(b64) {
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err == nil && utf8.Valid(decoded) && len(decoded) > 10 {
				preview := string(decoded)
				if len(preview) > 80 {
					preview = preview[:80] + "..."
				}
				add("base64", b64[:40]+"...", source, i18n.T("ioc_decoded")+preview)
			} else {
				add("base64", b64[:40]+"...", source, context)
			}
		}
	}
}

func isPublicIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	// Skip private/loopback/link-local
	if parts[0] == "10" || parts[0] == "127" || parts[0] == "0" {
		return false
	}
	if parts[0] == "192" && parts[1] == "168" {
		return false
	}
	if parts[0] == "172" {
		// 172.16-31.x.x
		second := 0
		for _, c := range parts[1] {
			second = second*10 + int(c-'0')
		}
		if second >= 16 && second <= 31 {
			return false
		}
	}
	if parts[0] == "169" && parts[1] == "254" {
		return false
	}
	return true
}

func isInterestingDomain(domain string) bool {
	// Must have at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// Reject file extensions masquerading as domains: cmd.exe, svchost.dll, etc.
	fileExts := []string{
		".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
		".hta", ".msi", ".scr", ".com", ".pif", ".wsf", ".sct",
		".tmp", ".log", ".ini", ".cfg", ".dat", ".db", ".xml",
		".json", ".txt", ".csv", ".doc", ".xls", ".pdf", ".zip",
		".lnk", ".url", ".inf", ".reg", ".cpl", ".ocx", ".drv",
	}
	for _, ext := range fileExts {
		if strings.HasSuffix(domain, ext) {
			return false
		}
	}

	// Reject if only one dot and looks like a filename (no real TLD structure)
	parts := strings.Split(domain, ".")
	if len(parts) == 2 && len(parts[1]) <= 3 {
		// Two-part "domain" with short TLD — likely a filename like "cmd.exe"
		// Real domains with short TLDs need at least a reasonable name part
		// Skip if the first part is a common system binary name
		commonBins := map[string]bool{
			"cmd": true, "powershell": true, "pwsh": true, "mshta": true,
			"rundll32": true, "regsvr32": true, "svchost": true, "csrss": true,
			"lsass": true, "services": true, "explorer": true, "conhost": true,
			"dllhost": true, "taskhost": true, "taskhostw": true, "dwm": true,
			"wscript": true, "cscript": true, "msiexec": true, "certutil": true,
			"bitsadmin": true, "msbuild": true, "installutil": true, "regasm": true,
			"wmic": true, "sc": true, "net": true, "net1": true, "netsh": true,
			"reg": true, "regedit": true, "notepad": true, "calc": true,
			"chrome": true, "firefox": true, "msedge": true, "iexplore": true,
			"winword": true, "excel": true, "outlook": true, "spoolsv": true,
		}
		if commonBins[parts[0]] {
			return false
		}
	}

	// Reject Windows path fragments that look like domains
	if strings.Contains(domain, `\`) || strings.Contains(domain, `/`) {
		return false
	}

	// Skip known common/boring domains
	boring := []string{
		"microsoft.com", "windows.com", "google.com", "gstatic.com",
		"googleapis.com", "apple.com", "adobe.com", "windowsupdate.com",
		"digicert.com", "verisign.com", "symantec.com", "globalsign.com",
		"w3.org", "schema.org", "xml.org", "mozilla.org", "github.com",
		"bing.com", "live.com", "office.com", "office365.com",
		"azure.com", "msn.com", "skype.com", "visualstudio.com",
		"aka.ms", "cloudflare.com", "akamai.com", "amazonaws.com",
	}
	for _, b := range boring {
		if domain == b || strings.HasSuffix(domain, "."+b) {
			return false
		}
	}

	// Require real TLD (at least 2 chars, must look like a domain not a file)
	tld := parts[len(parts)-1]
	validTLDs := map[string]bool{
		"com": true, "net": true, "org": true, "io": true, "co": true,
		"info": true, "biz": true, "me": true, "cc": true, "tv": true,
		"ru": true, "cn": true, "de": true, "uk": true, "fr": true,
		"jp": true, "kr": true, "br": true, "in": true, "au": true,
		"nl": true, "it": true, "es": true, "pl": true, "se": true,
		"top": true, "xyz": true, "site": true, "online": true, "club": true,
		"work": true, "tech": true, "store": true, "space": true,
		"live": true, "pro": true, "dev": true, "app": true,
		"edu": true, "gov": true, "mil": true, "int": true,
		"tk": true, "ml": true, "ga": true, "cf": true, "gq": true, // free TLDs often abused
	}
	if !validTLDs[tld] {
		return false
	}

	return true
}

func isLikelyBase64(s string) bool {
	if len(s) < 40 {
		return false
	}
	// Heuristic: if it has mixed case + digits + special base64 chars
	hasUpper, hasLower, hasDigit := false, false, false
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

func baseName(path string) string {
	if idx := strings.LastIndex(path, `\`); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
