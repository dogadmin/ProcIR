package module

import (
	"fmt"
	"strings"

	"procir/internal/i18n"
	"procir/internal/types"
)

// scoreModule applies detection rules to a single module.
func scoreModule(mi *types.ModuleInfo, ctx *types.ModuleAnalysis) {
	mi.Score = 0
	mi.Reasons = nil

	// === Base Rules ===

	// Unsigned DLL: +20
	if !mi.Signed {
		mi.Score += 20
		mi.Reasons = append(mi.Reasons, i18n.T("unsigned_dll"))
	}

	// User directory DLL: +25
	if mi.IsUserPath {
		mi.Score += 25
		mi.Reasons = append(mi.Reasons, i18n.T("user_dir_dll"))
	}

	// Temp directory DLL: +25
	if mi.IsTempPath {
		mi.Score += 25
		mi.Reasons = append(mi.Reasons, i18n.T("temp_dir_dll"))
	}

	// === Masquerade Detection ===

	// System DLL name + non-system path: +30
	if mi.IsSystemDLLName && !mi.IsSystemPath {
		mi.Score += 30
		mi.Reasons = append(mi.Reasons, i18n.T("sysdll_masquerade"))
		ctx.HasDLLHijack = true
	}

	// === Core Sideload Rules ===

	// Rule 1: Signed EXE + unsigned user-dir DLL (白加黑): +40
	if ctx.ExeSigned && !mi.Signed && mi.IsUserPath {
		mi.Score += 40
		mi.Reasons = append(mi.Reasons, i18n.T("dll_sideload"))
		ctx.HasDLLHijack = true
	}

	// Rule 2: Same-directory DLL + unsigned (classic sideload): +35
	if mi.IsSameDirAsExe && !mi.Signed {
		mi.Score += 35
		mi.Reasons = append(mi.Reasons, i18n.T("same_dir_sideload"))
		ctx.HasDLLHijack = true
	}

	// Rule 3: System process loading user-dir DLL → Critical
	exeLower := strings.ToLower(ctx.ExeName)
	if systemProcesses[exeLower] && (mi.IsUserPath || mi.IsTempPath) {
		mi.Score += 50
		mi.Reasons = append(mi.Reasons, i18n.T("sysproc_user_dll"))
		ctx.HasDLLHijack = true
	}

	// Combo: system DLL name + same directory + unsigned → strongest signal
	if mi.IsSystemDLLName && mi.IsSameDirAsExe && !mi.Signed {
		mi.Score += 20 // bonus on top
		mi.Reasons = append(mi.Reasons, i18n.T("classic_sideload"))
	}
}

// aggregateScore computes the overall module analysis score.
func aggregateScore(result *types.ModuleAnalysis) {
	if result.SuspiciousCount == 0 {
		return
	}

	// Take max module score as base
	maxScore := 0
	for _, m := range result.SuspiciousModules {
		if m.Score > maxScore {
			maxScore = m.Score
		}
	}
	result.Score = maxScore
	result.DLLHijackScore = maxScore

	// Rule 4: Multiple suspicious modules: +20
	if result.SuspiciousCount >= 2 {
		result.Score += 20
		result.Reasons = append(result.Reasons, fmt.Sprintf(i18n.T("multi_susp_modules"), result.SuspiciousCount))
	}

	// Collect all reasons from suspicious modules
	for _, m := range result.SuspiciousModules {
		for _, r := range m.Reasons {
			result.Reasons = appendUnique(result.Reasons, r)
		}
	}

	// Override: system process + user DLL → Critical (>=80)
	exeLower := strings.ToLower(result.ExeName)
	for _, m := range result.SuspiciousModules {
		if systemProcesses[exeLower] && (m.IsUserPath || m.IsTempPath) {
			if result.Score < 80 {
				result.Score = 80
			}
			break
		}
	}

	// Override: same-dir + system DLL name masquerade → Critical
	for _, m := range result.SuspiciousModules {
		if m.IsSameDirAsExe && m.IsSystemDLLName && !m.Signed {
			if result.Score < 80 {
				result.Score = 80
			}
			break
		}
	}

	result.DLLHijackScore = result.Score
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

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
