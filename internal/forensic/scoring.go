package forensic

import (
	"strings"
	"time"

	"procir/internal/i18n"
	"procir/internal/types"
)

// ScoreAll scores all forensic entries.
func ScoreAll(entries []*types.ForensicEntry) {
	for _, e := range entries {
		scoreEntry(e)
	}
}

func scoreEntry(e *types.ForensicEntry) {
	e.Score = 0
	if e.Reasons == nil {
		e.Reasons = []string{}
	}

	pathLower := strings.ToLower(e.Path)
	cmdLower := strings.ToLower(e.CommandLine)

	switch e.Source {
	case types.ForensicPrefetch:
		scorePrefetch(e, pathLower)
	case types.ForensicRecentFile:
		scoreRecentFile(e, pathLower)
	case types.ForensicEventLog:
		scoreEventLog(e, pathLower, cmdLower)
	case types.ForensicModule:
		scoreModule(e)
	}
}

func scorePrefetch(e *types.ForensicEntry, _ string) {
	exeLower := strings.ToLower(e.ExeName)

	// Check if exe name suggests user directory execution
	// Prefetch doesn't store full path in filename, but unusual names are suspicious
	e.Score += 5
	e.Reasons = append(e.Reasons, i18n.T("fore_prefetch"))

	// Recent execution (within 24h)
	if isRecentTime(e.LastRunTime, 24*time.Hour) {
		e.Score += 10
		e.Reasons = append(e.Reasons, i18n.T("fore_24h_exec"))
	} else if isRecentTime(e.LastRunTime, 72*time.Hour) {
		e.Score += 5
		e.Reasons = append(e.Reasons, i18n.T("fore_72h_exec"))
	}

	// LOLBin prefetch
	if isLOLBinName(exeLower) {
		e.Score += 5
		e.Reasons = append(e.Reasons, i18n.T("fore_lolbin_trace"))
	}

	// Suspicious names (often malware patterns)
	if len(exeLower) <= 5 || strings.Contains(exeLower, "tmp") ||
		strings.Contains(exeLower, "temp") || strings.HasPrefix(exeLower, "a.") ||
		strings.HasPrefix(exeLower, "1.") || strings.HasPrefix(exeLower, "x.") {
		e.Score += 15
		e.Reasons = append(e.Reasons, i18n.T("fore_susp_filename"))
	}
}

func scoreRecentFile(e *types.ForensicEntry, pathLower string) {
	// Base score for recent suspicious file
	isRecent24h := isRecentTime(e.FileModTime, 24*time.Hour)

	switch e.FileType {
	case "exe":
		if isRecent24h {
			e.Score += 20
			e.Reasons = append(e.Reasons, i18n.T("fore_24h_exe"))
		} else {
			e.Score += 15
			e.Reasons = append(e.Reasons, i18n.T("fore_72h_exe"))
		}
	case "dll":
		if isRecent24h {
			e.Score += 18
			e.Reasons = append(e.Reasons, i18n.T("fore_24h_dll"))
		} else {
			e.Score += 12
			e.Reasons = append(e.Reasons, i18n.T("fore_72h_dll"))
		}
	case "script":
		if isRecent24h {
			e.Score += 15
			e.Reasons = append(e.Reasons, i18n.T("fore_24h_script"))
		} else {
			e.Score += 10
			e.Reasons = append(e.Reasons, i18n.T("fore_72h_script"))
		}
	}

	// User directory
	if strings.HasPrefix(pathLower, `c:\users\`) {
		e.Score += 10
		e.Reasons = append(e.Reasons, i18n.T("fore_user_dir"))
	}

	// Temp directory
	if strings.Contains(pathLower, `\temp\`) || strings.Contains(pathLower, `\tmp\`) {
		e.Score += 10
		e.Reasons = append(e.Reasons, i18n.T("fore_temp_dir"))
	}

	// ProgramData
	if strings.HasPrefix(pathLower, `c:\programdata\`) {
		e.Score += 5
		e.Reasons = append(e.Reasons, i18n.T("fore_programdata_dir"))
	}
}

func scoreEventLog(e *types.ForensicEntry, pathLower, cmdLower string) {
	switch e.EventID {
	case 4688: // Process creation
		e.Score += 10
		e.Reasons = append(e.Reasons, i18n.T("fore_hist_proc"))

		if strings.Contains(pathLower, `\users\`) || strings.Contains(pathLower, `\temp\`) {
			e.Score += 10
			e.Reasons = append(e.Reasons, i18n.T("fore_hist_user_temp"))
		}

		if strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "frombase64") {
			e.Score += 20
			e.Reasons = append(e.Reasons, i18n.T("fore_hist_encoded"))
		}

		if strings.Contains(cmdLower, "downloadstring") || strings.Contains(cmdLower, "invoke-webrequest") ||
			strings.Contains(cmdLower, "net.webclient") {
			e.Score += 20
			e.Reasons = append(e.Reasons, i18n.T("fore_hist_download"))
		}

	case 4104: // PowerShell script block
		e.Score += 15
		e.Reasons = append(e.Reasons, i18n.T("fore_hist_ps_susp"))

		if strings.Contains(cmdLower, "invoke-mimikatz") || strings.Contains(cmdLower, "invoke-shellcode") ||
			strings.Contains(cmdLower, "amsiutils") {
			e.Score += 30
			e.Reasons = append(e.Reasons, i18n.T("fore_hist_ps_tool"))
		}

	case 7045: // Service installation
		e.Score += 15
		e.Reasons = append(e.Reasons, i18n.T("fore_hist_svc_install"))

		if strings.Contains(pathLower, `\users\`) || strings.Contains(pathLower, `\temp\`) {
			e.Score += 15
			e.Reasons = append(e.Reasons, i18n.T("fore_hist_svc_user_temp"))
		}

		if strings.Contains(cmdLower, "powershell") || strings.Contains(cmdLower, "cmd") ||
			strings.Contains(cmdLower, "mshta") {
			e.Score += 15
			e.Reasons = append(e.Reasons, i18n.T("fore_hist_svc_script"))
		}

	case 4698: // Task creation
		e.Score += 15
		e.Reasons = append(e.Reasons, i18n.T("fore_hist_task"))
	}
}

func scoreModule(e *types.ForensicEntry) {
	// Base score from reasons already set in collector
	for _, r := range e.Reasons {
		switch r {
		case i18n.T("user_dir_dll"):
			e.Score += 25
		case i18n.T("temp_dir_dll"):
			e.Score += 25
		case i18n.T("sysdll_masquerade"):
			e.Score += 25
		case i18n.T("programdata_exec"):
			e.Score += 15
		case i18n.T("fore_unsigned"):
			e.Score += 20
		}
	}
}

func isRecentTime(timeStr string, duration time.Duration) bool {
	t, err := time.ParseInLocation("2006-01-02 15:04:05", timeStr, time.Local)
	if err != nil {
		return false
	}
	return time.Since(t) < duration
}

func isLOLBinName(name string) bool {
	lolbins := []string{
		"powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe",
		"wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
		"certutil.exe", "bitsadmin.exe", "msiexec.exe",
	}
	for _, l := range lolbins {
		if name == l {
			return true
		}
	}
	return false
}
