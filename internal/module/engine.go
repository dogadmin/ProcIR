package module

import (
	"sort"
	"strings"
	"sync"

	"procir/internal/i18n"
	"procir/internal/types"
)

// AnalyzeResult holds all module analysis results.
type AnalyzeResult struct {
	Analyses []*types.ModuleAnalysis
}

// AnalyzeAll analyzes modules for all processes.
// Only analyzes processes that are worth checking (non-system-only, or high risk).
func AnalyzeAll(processes []*types.ProcessRecord) *AnalyzeResult {
	var mu sync.Mutex
	var results []*types.ModuleAnalysis

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4) // limit concurrency for module enumeration

	for _, p := range processes {
		if !shouldAnalyze(p) {
			continue
		}

		wg.Add(1)
		go func(proc *types.ProcessRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			analysis := AnalyzeProcess(
				proc.PID, proc.Name, proc.Path,
				proc.Signed, proc.Signer,
			)

			if analysis != nil && analysis.SuspiciousCount > 0 {
				mu.Lock()
				results = append(results, analysis)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()

	// Sort by score descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return &AnalyzeResult{Analyses: results}
}

// ApplyToObjects applies module analysis results to ExecutionObjects.
func ApplyToObjects(analyses []*types.ModuleAnalysis, objects []*types.ExecutionObject) {
	// Build index: exe path → analysis
	pathIndex := make(map[string][]*types.ModuleAnalysis)
	for _, a := range analyses {
		key := strings.ToLower(a.ExePath)
		pathIndex[key] = append(pathIndex[key], a)
	}

	for _, obj := range objects {
		key := strings.ToLower(obj.Path)
		moduleAnalyses, ok := pathIndex[key]
		if !ok {
			continue
		}

		obj.ModuleAnalyses = moduleAnalyses

		// Aggregate across all analyses for this object
		totalSuspicious := 0
		maxScore := 0
		hasDLLHijack := false

		for _, a := range moduleAnalyses {
			totalSuspicious += a.SuspiciousCount
			if a.Score > maxScore {
				maxScore = a.Score
			}
			if a.HasDLLHijack {
				hasDLLHijack = true
			}
			for _, r := range a.Reasons {
				obj.Reasons = appendUnique(obj.Reasons, i18n.T("mod_prefix")+r)
			}
		}

		obj.SuspiciousModuleCount = totalSuspicious
		obj.HasDLLHijack = hasDLLHijack
		obj.DLLHijackScore = maxScore

		// Apply score to FinalScore
		obj.FinalScore += maxScore

		// Synergy: DLL hijack + network
		if hasDLLHijack && obj.NetworkObserved {
			obj.FinalScore += 20
			obj.Reasons = append(obj.Reasons, i18n.T("mod_fusion_hijack_net"))
		}

		// Synergy: DLL hijack + persistence
		if hasDLLHijack && obj.TriggerCount > 0 {
			obj.FinalScore += 20
			obj.Reasons = append(obj.Reasons, i18n.T("mod_fusion_hijack_persist"))
		}

		obj.RiskLevel = types.CalcRiskLevel(obj.FinalScore)
	}
}

// shouldAnalyze decides if a process is worth analyzing for module abuse.
func shouldAnalyze(p *types.ProcessRecord) bool {
	if p.PID == 0 || p.PID == 4 || p.Path == "" {
		return false
	}

	// Always analyze high-risk processes
	if p.RiskScore >= 20 {
		return true
	}

	// Always analyze processes from user/temp dirs
	if p.PathAbnormal {
		return true
	}

	// Always analyze processes with network connections
	if p.HasNetwork && len(p.RemoteIPs) > 0 {
		return true
	}

	// Always analyze signed processes (they're sideload targets)
	if p.Signed {
		return true
	}

	// Analyze system processes (they shouldn't load user DLLs)
	nameLower := strings.ToLower(p.Name)
	if systemProcesses[nameLower] {
		return true
	}

	return false
}
