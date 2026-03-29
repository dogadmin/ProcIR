package fusion

import (
	"fmt"
	"sort"
	"strings"

	"procir/internal/context"
	"procir/internal/i18n"
	"procir/internal/types"
)

// Fuse merges ProcessRecords, TriggerEntries, and ForensicEntries into unified ExecutionObjects.
func Fuse(processes []*types.ProcessRecord, triggers []*types.TriggerEntry, forensics []*types.ForensicEntry) []*types.ExecutionObject {
	// Index: normalized path → ExecutionObject
	objMap := make(map[string]*types.ExecutionObject)

	// Step 1: Add all processes
	for _, p := range processes {
		if p.Path == "" {
			continue
		}
		key := normalizePath(p.Path)

		obj, ok := objMap[key]
		if !ok {
			obj = &types.ExecutionObject{
				Path:    p.Path,
				ObjType: classifyType(p.Path),
			}
			objMap[key] = obj
		}

		obj.IsRunning = true
		obj.PIDs = append(obj.PIDs, p.PID)
		obj.ProcessNames = appendUnique(obj.ProcessNames, p.Name)
		obj.Processes = append(obj.Processes, p)

		if !contains(obj.Sources, "process") {
			obj.Sources = append(obj.Sources, "process")
		}

		// Take best file info
		if p.SHA256 != "" && obj.SHA256 == "" {
			obj.SHA256 = p.SHA256
			obj.MD5 = p.MD5
		}
		if p.Signed {
			obj.Signed = p.Signed
			obj.SignValid = p.SignValid
			obj.Signer = p.Signer
			obj.Company = p.Company
			obj.Product = p.Product
			obj.OriginalName = p.OriginalName
		}
		obj.Exists = p.FileExists
		obj.FileSize = p.FileSize
		obj.IsLOLBin = obj.IsLOLBin || p.IsLOLBin

		if p.HasNetwork {
			obj.NetworkObserved = true
			for _, ip := range p.RemoteIPs {
				obj.RemoteIPs = appendUnique(obj.RemoteIPs, ip)
			}
		}
		obj.HasPublicIP = obj.HasPublicIP || p.HasPublicIP

		// Track max execution score
		if p.RiskScore > obj.ExecutionScore {
			obj.ExecutionScore = p.RiskScore
		}
	}

	// Step 2: Add all triggers
	for _, t := range triggers {
		if t.Path == "" && t.CommandLine == "" {
			continue
		}

		key := normalizePath(t.Path)
		if key == "" {
			key = normalizeCmd(t.CommandLine)
		}
		if key == "" {
			continue
		}

		obj, ok := objMap[key]
		if !ok {
			obj = &types.ExecutionObject{
				Path:    t.Path,
				ObjType: classifyType(t.Path),
			}
			if t.Path == "" {
				obj.Path = t.CommandLine
				obj.ObjType = "command"
			}
			objMap[key] = obj
		}

		obj.Triggers = append(obj.Triggers, t)

		srcName := string(t.Type)
		if !contains(obj.Sources, srcName) {
			obj.Sources = append(obj.Sources, srcName)
			obj.TriggerTypes = append(obj.TriggerTypes, srcName)
		}
		obj.TriggerCount++

		// Accumulate trigger score (take max per type, sum across types)
		if t.Score > obj.TriggerScore {
			obj.TriggerScore = t.Score
		}

		// Merge trigger's command line for analysis
		if obj.CommandLine == "" && t.CommandLine != "" {
			obj.CommandLine = t.CommandLine
		}
	}

	// Step 3: Add forensic entries
	for _, f := range forensics {
		if f.Path == "" {
			continue
		}

		key := normalizePath(f.Path)
		if key == "" {
			continue
		}

		obj, ok := objMap[key]
		if !ok {
			obj = &types.ExecutionObject{
				Path:    f.Path,
				ObjType: classifyType(f.Path),
			}
			objMap[key] = obj
		}

		obj.Forensics = append(obj.Forensics, f)
		obj.ForensicHits++

		srcName := string(f.Source)
		if !contains(obj.Sources, srcName) {
			obj.Sources = append(obj.Sources, srcName)
		}

		switch f.Source {
		case types.ForensicPrefetch:
			obj.HasPrefetch = true
		case types.ForensicEventLog:
			obj.HasEventLog = true
		case types.ForensicRecentFile:
			obj.HasRecentFile = true
		case types.ForensicModule:
			obj.SuspiciousModules++
		}

		if f.Score > obj.ForensicScore {
			obj.ForensicScore = f.Score
		}
	}

	// Step 4: Set location type for all objects
	for _, obj := range objMap {
		obj.LocationType = classifyLocation(obj.Path)
	}

	// Step 5: Apply fusion scoring
	for _, obj := range objMap {
		scoreFusion(obj)
	}

	// Step 6: Convert to sorted slice
	var result []*types.ExecutionObject
	for _, obj := range objMap {
		result = append(result, obj)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].FinalScore > result[j].FinalScore
	})

	return result
}

// scoreFusion applies the fusion scoring model to an ExecutionObject.
func scoreFusion(obj *types.ExecutionObject) {
	obj.Reasons = nil

	// Base: ExecutionScore + TriggerScore + ForensicScore
	obj.FinalScore = obj.ExecutionScore + obj.TriggerScore + obj.ForensicScore

	if obj.IsRunning {
		obj.Reasons = append(obj.Reasons, i18n.T("fus_running"))
	}
	if obj.TriggerCount > 0 {
		obj.Reasons = append(obj.Reasons, fmt.Sprintf(i18n.T("fus_triggers"), obj.TriggerCount, strings.Join(obj.TriggerTypes, "+")))
	}
	if obj.ForensicHits > 0 {
		obj.Reasons = append(obj.Reasons, fmt.Sprintf(i18n.T("fus_forensic_traces"), obj.ForensicHits))
	}

	// Copy process-level reasons
	for _, p := range obj.Processes {
		for _, r := range p.Reasons {
			obj.Reasons = appendUnique(obj.Reasons, r)
		}
	}

	// Copy trigger-level reasons
	for _, t := range obj.Triggers {
		for _, r := range t.Reasons {
			obj.Reasons = appendUnique(obj.Reasons, r)
		}
	}

	// Copy forensic-level reasons
	for _, f := range obj.Forensics {
		for _, r := range f.Reasons {
			obj.Reasons = appendUnique(obj.Reasons, r)
		}
	}

	// --- Fusion Override Rules ---
	overrideMin := 0

	// Rule 1: Not running but high trigger score → at least Medium
	if !obj.IsRunning && obj.TriggerScore >= 40 {
		if overrideMin < 40 {
			overrideMin = 40
			obj.Reasons = append(obj.Reasons, i18n.T("fus_not_running_high_trigger"))
		}
	}

	// Rule 2: Trigger contains PowerShell -enc → High/Critical
	for _, t := range obj.Triggers {
		cmdLower := strings.ToLower(t.CommandLine)
		if (t.Type == types.TriggerTask || t.Type == types.TriggerWMI || t.Type == types.TriggerRunKey) &&
			(strings.Contains(cmdLower, "powershell") || strings.Contains(cmdLower, "pwsh")) &&
			(strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "-encodedcommand")) {
			if overrideMin < 80 {
				overrideMin = 80
				obj.Reasons = append(obj.Reasons, i18n.T("fus_strong_ps_encoded"))
			}
		}
	}

	// Rule 3: User dir + auto-start trigger
	if isUserLocation(obj.LocationType) {
		for _, t := range obj.Triggers {
			if t.Type == types.TriggerRunKey || t.Type == types.TriggerTask || t.Type == types.TriggerService {
				obj.SynergyBonus += 20
				obj.Reasons = append(obj.Reasons, i18n.T("fus_userdir_autostart"))
				break
			}
		}
	}

	// Rule 4: Persistence + network (if running)
	if obj.IsRunning && obj.NetworkObserved && obj.TriggerCount > 0 {
		obj.SynergyBonus += 20
		obj.Reasons = append(obj.Reasons, i18n.T("fus_running_network_persist"))
	}

	// Rule 5: Multiple trigger chains → Critical
	uniqueTypes := make(map[types.TriggerType]bool)
	for _, t := range obj.Triggers {
		uniqueTypes[t.Type] = true
	}
	if len(uniqueTypes) >= 3 {
		if overrideMin < 80 {
			overrideMin = 80
			obj.Reasons = append(obj.Reasons, i18n.T("fus_strong_multi_trigger_chain"))
		}
	} else if len(uniqueTypes) >= 2 {
		obj.SynergyBonus += 20
		obj.Reasons = append(obj.Reasons, i18n.T("fus_multi_trigger_same_obj"))
	}

	// --- Forensic Fusion Rules ---

	// Rule 6: Not running but has execution history → +15
	if !obj.IsRunning && obj.HasPrefetch {
		obj.SynergyBonus += 15
		obj.Reasons = append(obj.Reasons, i18n.T("fus_not_running_has_trace"))
	}

	// Rule 7: Recent execution + persistence → +20
	if obj.HasPrefetch && obj.TriggerCount > 0 {
		obj.SynergyBonus += 20
		obj.Reasons = append(obj.Reasons, i18n.T("fus_history_exec_persist"))
	}

	// Rule 8: Forensic hit + trigger → +20
	if obj.HasEventLog && obj.TriggerCount > 0 {
		obj.SynergyBonus += 20
		obj.Reasons = append(obj.Reasons, i18n.T("fus_eventlog_trigger"))
	}

	// Rule 9: File disappeared but has forensic record → Suspicious
	if !obj.Exists && obj.ForensicHits > 0 && !obj.IsRunning {
		if overrideMin < 20 {
			overrideMin = 20
			obj.Reasons = append(obj.Reasons, i18n.T("fus_file_deleted_has_trace"))
		}
	}

	// Rule 10: Suspicious modules → High
	if obj.SuspiciousModules >= 2 {
		if overrideMin < 60 {
			overrideMin = 60
			obj.Reasons = append(obj.Reasons, i18n.T("fus_strong_suspicious_modules"))
		}
	}

	// --- White Signals ---
	if obj.Signed && obj.SignValid && context.IsTrustedVendor(obj.Signer, obj.Company) {
		obj.WhiteReduction += 15
	}
	if obj.LocationType == "System32" && obj.Signed && obj.SignValid {
		obj.WhiteReduction += 10
	}

	// Apply
	obj.FinalScore += obj.SynergyBonus
	obj.FinalScore -= obj.WhiteReduction

	if obj.FinalScore < overrideMin {
		obj.FinalScore = overrideMin
	}
	if obj.FinalScore < 0 {
		obj.FinalScore = 0
	}

	obj.RiskLevel = types.CalcRiskLevel(obj.FinalScore)

	// Build source detail
	var parts []string
	if obj.IsRunning {
		parts = append(parts, fmt.Sprintf(i18n.T("fus_running_pid"), obj.PIDs))
	}
	for _, t := range obj.Triggers {
		parts = append(parts, t.Detail)
	}
	obj.SourceDetail = strings.Join(parts, " | ")
}

func normalizePath(path string) string {
	if path == "" {
		return ""
	}
	p := strings.ToLower(strings.TrimSpace(path))
	p = strings.Trim(p, `"`)
	// Expand environment variables
	p = strings.ReplaceAll(p, `%systemroot%`, `c:\windows`)
	p = strings.ReplaceAll(p, `%windir%`, `c:\windows`)
	return p
}

func normalizeCmd(cmd string) string {
	return strings.ToLower(strings.TrimSpace(cmd))
}

func classifyType(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".dll"):
		return "dll"
	case strings.HasSuffix(lower, ".ps1"), strings.HasSuffix(lower, ".vbs"),
		strings.HasSuffix(lower, ".js"), strings.HasSuffix(lower, ".bat"),
		strings.HasSuffix(lower, ".cmd"):
		return "script"
	case strings.HasSuffix(lower, ".exe"):
		return "exe"
	default:
		return "other"
	}
}

func classifyLocation(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasPrefix(lower, `c:\windows\system32`) || strings.HasPrefix(lower, `c:\windows\syswow64`):
		return "System32"
	case strings.HasPrefix(lower, `c:\program files\`) || strings.HasPrefix(lower, `c:\program files (x86)\`):
		return "ProgramFiles"
	case strings.HasPrefix(lower, `c:\programdata\`):
		return "ProgramData"
	case strings.HasPrefix(lower, `c:\users\`):
		return "UserDir"
	case strings.Contains(lower, `\temp\`) || strings.Contains(lower, `\tmp\`):
		return "Temp"
	case strings.HasPrefix(lower, `c:\windows\`):
		return "Windows"
	default:
		return "Other"
	}
}

func isUserLocation(loc string) bool {
	return loc == "UserDir" || loc == "Temp"
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func appendUnique(slice []string, s string) []string {
	if !contains(slice, s) {
		return append(slice, s)
	}
	return slice
}
