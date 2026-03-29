package forensic

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"procir/internal/i18n"
	"procir/internal/types"
)

// collectEventLogs queries Windows Event Logs for security-relevant events.
func collectEventLogs() []*types.ForensicEntry {
	var results []*types.ForensicEntry

	// Query recent process creation events (Event ID 4688) - last 72 hours
	results = append(results, queryProcessCreation()...)

	// Query PowerShell script block logging (Event ID 4104)
	results = append(results, queryPowerShell()...)

	// Query new service installation (Event ID 7045)
	results = append(results, queryServiceInstall()...)

	// Query scheduled task creation (Event ID 4698)
	results = append(results, queryTaskCreation()...)

	return results
}

// XML structures for wevtutil output
type events struct {
	XMLName xml.Name `xml:"Events"`
	Events  []event  `xml:"Event"`
}

type event struct {
	System   eventSystem `xml:"System"`
	EventData eventData  `xml:"EventData"`
}

type eventSystem struct {
	EventID     int    `xml:"EventID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	Computer string `xml:"Computer"`
}

type eventData struct {
	Data []eventDataItem `xml:"Data"`
}

type eventDataItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

func (ed *eventData) get(name string) string {
	for _, d := range ed.Data {
		if d.Name == name {
			return d.Value
		}
	}
	return ""
}

func queryProcessCreation() []*types.ForensicEntry {
	// Event ID 4688: A new process has been created
	// Query last 72 hours, max 500 events
	xml, err := wevtutil("Security",
		"*[System[EventID=4688 and TimeCreated[timediff(@SystemTime) <= 259200000]]]", 500)
	if err != nil {
		return nil
	}

	var results []*types.ForensicEntry
	for _, evt := range xml {
		newProcessName := evt.EventData.get("NewProcessName")
		cmdLine := evt.EventData.get("CommandLine")
		parentProcess := evt.EventData.get("ParentProcessName")
		user := evt.EventData.get("SubjectUserName")

		if newProcessName == "" {
			continue
		}

		// Only flag interesting ones
		nameLower := strings.ToLower(newProcessName)
		cmdLower := strings.ToLower(cmdLine)
		interesting := false

		// User directory execution
		if strings.Contains(nameLower, `\users\`) || strings.Contains(nameLower, `\temp\`) ||
			strings.Contains(nameLower, `\programdata\`) {
			interesting = true
		}

		// LOLBin with suspicious args
		if isLOLBinPath(nameLower) && hasSuspiciousArgs(cmdLower) {
			interesting = true
		}

		// PowerShell encoded
		if strings.Contains(nameLower, "powershell") && strings.Contains(cmdLower, "-enc") {
			interesting = true
		}

		if !interesting {
			continue
		}

		timeStr := parseEventTime(evt.System.TimeCreated.SystemTime)

		fe := &types.ForensicEntry{
			Source:      types.ForensicEventLog,
			Path:        newProcessName,
			CommandLine: cmdLine,
			EventID:     4688,
			EventTime:   timeStr,
			EventSource: "Security",
			Detail:      fmt.Sprintf(i18n.T("fore_proc_create_4688"), baseName(parentProcess), baseName(newProcessName), user, timeStr),
		}

		results = append(results, fe)
	}

	return results
}

func queryPowerShell() []*types.ForensicEntry {
	// Event ID 4104: Script block logging
	xml, err := wevtutil("Microsoft-Windows-PowerShell/Operational",
		"*[System[EventID=4104 and TimeCreated[timediff(@SystemTime) <= 259200000]]]", 200)
	if err != nil {
		return nil
	}

	var results []*types.ForensicEntry
	for _, evt := range xml {
		scriptBlock := evt.EventData.get("ScriptBlockText")
		if scriptBlock == "" {
			continue
		}

		lower := strings.ToLower(scriptBlock)
		interesting := false

		// Only flag suspicious script blocks
		suspiciousPatterns := []string{
			"invoke-expression", "iex ", "iex(", "downloadstring", "downloadfile",
			"invoke-webrequest", "net.webclient", "encodedcommand", "frombase64",
			"invoke-mimikatz", "invoke-shellcode", "amsiutils", "bypass",
			"reflection.assembly", "getprocaddress", "virtualalloc",
			"invoke-command", "enter-pssession", "new-pssession",
		}

		for _, p := range suspiciousPatterns {
			if strings.Contains(lower, p) {
				interesting = true
				break
			}
		}

		if !interesting {
			continue
		}

		timeStr := parseEventTime(evt.System.TimeCreated.SystemTime)

		snippet := scriptBlock
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}

		fe := &types.ForensicEntry{
			Source:      types.ForensicEventLog,
			Path:        "powershell",
			CommandLine: snippet,
			EventID:     4104,
			EventTime:   timeStr,
			EventSource: "PowerShell/Operational",
			Detail:      fmt.Sprintf(i18n.T("fore_ps_script_4104"), truncStr(snippet, 100), timeStr),
		}

		results = append(results, fe)
	}

	return results
}

func queryServiceInstall() []*types.ForensicEntry {
	// Event ID 7045: A new service was installed
	xml, err := wevtutil("System",
		"*[System[EventID=7045 and TimeCreated[timediff(@SystemTime) <= 604800000]]]", 100)
	if err != nil {
		return nil
	}

	var results []*types.ForensicEntry
	for _, evt := range xml {
		serviceName := evt.EventData.get("ServiceName")
		imagePath := evt.EventData.get("ImagePath")
		serviceType := evt.EventData.get("ServiceType")
		startType := evt.EventData.get("StartType")

		if serviceName == "" {
			continue
		}

		timeStr := parseEventTime(evt.System.TimeCreated.SystemTime)

		fe := &types.ForensicEntry{
			Source:      types.ForensicEventLog,
			Path:        imagePath,
			EventID:     7045,
			EventTime:   timeStr,
			EventSource: "System",
			Detail:      fmt.Sprintf(i18n.T("fore_svc_install_7045"), serviceName, truncStr(imagePath, 80), serviceType, startType, timeStr),
		}

		results = append(results, fe)
	}

	return results
}

func queryTaskCreation() []*types.ForensicEntry {
	// Event ID 4698: A scheduled task was created
	xml, err := wevtutil("Security",
		"*[System[EventID=4698 and TimeCreated[timediff(@SystemTime) <= 604800000]]]", 100)
	if err != nil {
		return nil
	}

	var results []*types.ForensicEntry
	for _, evt := range xml {
		taskName := evt.EventData.get("TaskName")
		taskContent := evt.EventData.get("TaskContent")
		user := evt.EventData.get("SubjectUserName")

		if taskName == "" {
			continue
		}

		timeStr := parseEventTime(evt.System.TimeCreated.SystemTime)

		fe := &types.ForensicEntry{
			Source:      types.ForensicEventLog,
			Path:        taskName,
			CommandLine: taskContent,
			EventID:     4698,
			EventTime:   timeStr,
			EventSource: "Security",
			Detail:      fmt.Sprintf(i18n.T("fore_task_create_4698"), taskName, user, timeStr),
		}

		results = append(results, fe)
	}

	return results
}

// wevtutil runs a Windows Event Log query and returns parsed events.
func wevtutil(logName, query string, maxEvents int) ([]event, error) {
	cmd := exec.Command("wevtutil", "qe", logName,
		fmt.Sprintf("/q:%s", query),
		fmt.Sprintf("/c:%d", maxEvents),
		"/f:xml", "/rd:true")

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// wevtutil outputs multiple <Event> elements, wrap in root
	xmlStr := "<Events>" + string(out) + "</Events>"

	var evts events
	if err := xml.Unmarshal([]byte(xmlStr), &evts); err != nil {
		return nil, err
	}

	return evts.Events, nil
}

func parseEventTime(systemTime string) string {
	// Format: 2024-01-15T10:30:00.000000000Z
	t, err := time.Parse(time.RFC3339Nano, systemTime)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05.000000000Z", systemTime)
		if err != nil {
			return systemTime
		}
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func baseName(path string) string {
	if idx := strings.LastIndex(path, `\`); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func isLOLBinPath(path string) bool {
	lolbins := []string{
		"powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe",
		"wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
		"certutil.exe", "bitsadmin.exe", "msiexec.exe", "msbuild.exe",
	}
	for _, l := range lolbins {
		if strings.HasSuffix(path, `\`+l) {
			return true
		}
	}
	return false
}

func hasSuspiciousArgs(cmd string) bool {
	patterns := []string{
		"-enc ", "-encodedcommand", "frombase64", "downloadstring",
		"invoke-expression", "iex ", "-w hidden", "/i:http",
		"javascript:", "vbscript:", "-urlcache", "/transfer",
	}
	for _, p := range patterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}
