package yara

import (
	"path/filepath"
	"strings"
	"sync"

	"procir/internal/i18n"
	"procir/internal/types"
)

// YaraHit represents a single YARA rule match.
type YaraHit struct {
	RuleName   string            `json:"RuleName"`
	Namespace  string            `json:"Namespace"`
	Tags       []string          `json:"Tags"`
	Strings    []string          `json:"Strings"`
	Meta       map[string]string `json:"Meta"`
	TargetPath string            `json:"TargetPath"`
}

// Engine manages YARA scanning.
type Engine struct {
	ruleSet *RuleSet
	cache   *ScanCache
	enabled bool
}

// NewEngine creates a YARA engine. Returns nil if no rules are loaded.
func NewEngine(rulePath string) *Engine {
	if rulePath == "" {
		return nil
	}

	rs, err := LoadRules(rulePath)
	if err != nil || rs == nil || len(rs.Rules) == 0 {
		return nil
	}

	return &Engine{
		ruleSet: rs,
		cache:   NewScanCache(rs.Hash),
		enabled: true,
	}
}

// ScanObjects scans a list of ExecutionObjects with YARA rules.
func (e *Engine) ScanObjects(objects []*types.ExecutionObject) {
	if e == nil || !e.enabled || e.ruleSet == nil {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4) // limit concurrency

	for _, obj := range objects {
		if !shouldScan(obj) {
			continue
		}

		wg.Add(1)
		go func(o *types.ExecutionObject) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			e.scanObject(o)
		}(obj)
	}

	wg.Wait()
}

// ScanSingleFile scans a single file path. For manual/right-click scanning.
func (e *Engine) ScanSingleFile(path string) []YaraHit {
	if e == nil || !e.enabled || e.ruleSet == nil {
		return nil
	}

	if hits, ok := e.cache.Get(path); ok {
		return hits
	}

	hits := ScanFile(path, e.ruleSet)
	e.cache.Set(path, hits)
	return hits
}

func (e *Engine) scanObject(obj *types.ExecutionObject) {
	path := obj.Path
	if path == "" || !obj.Exists {
		return
	}

	// Check extension filter
	if !isScannable(path) {
		return
	}

	// Check cache
	if hits, ok := e.cache.Get(path); ok {
		applyHits(obj, hits)
		return
	}

	// Scan
	hits := ScanFile(path, e.ruleSet)
	e.cache.Set(path, hits)
	applyHits(obj, hits)
}

// applyHits applies YARA results to an ExecutionObject and calculates YaraScore.
func applyHits(obj *types.ExecutionObject, hits []YaraHit) {
	if len(hits) == 0 {
		return
	}

	obj.YaraMatched = true
	obj.YaraHits = hits

	score := 0

	for _, hit := range hits {
		// Base: +20 per rule
		ruleScore := 20

		// High-risk tags: +30 instead
		for _, tag := range hit.Tags {
			tl := strings.ToLower(tag)
			if tl == "backdoor" || tl == "loader" || tl == "inject" ||
				tl == "credential" || tl == "beacon" || tl == "ransomware" ||
				tl == "trojan" || tl == "malware" || tl == "exploit" ||
				tl == "webshell" || tl == "rat" || tl == "keylogger" ||
				tl == "stealer" || tl == "miner" || tl == "rootkit" {
				ruleScore = 30
				break
			}
		}

		// Check meta for severity
		if sev, ok := hit.Meta["severity"]; ok {
			sl := strings.ToLower(sev)
			if sl == "critical" || sl == "high" {
				ruleScore = 30
			}
		}

		score += ruleScore
	}

	// Multi-rule bonus: +15
	if len(hits) >= 2 {
		score += 15
	}

	// Synergy: YARA + network
	if obj.NetworkObserved {
		score += 20
		obj.Reasons = append(obj.Reasons, i18n.T("yara_fusion_hit_network"))
	}

	// Synergy: YARA + persistence
	if obj.TriggerCount > 0 {
		score += 15
		obj.Reasons = append(obj.Reasons, i18n.T("yara_fusion_hit_persist"))
	}

	// Synergy: YARA + running
	if obj.IsRunning {
		score += 15
		obj.Reasons = append(obj.Reasons, i18n.T("yara_fusion_hit_running"))
	}

	obj.YaraScore = score
	obj.FinalScore += score
	obj.RiskLevel = types.CalcRiskLevel(obj.FinalScore)

	// Add reasons
	for _, hit := range hits {
		reason := i18n.T("yara_fusion_prefix") + " " + hit.RuleName
		if len(hit.Tags) > 0 {
			reason += " [" + strings.Join(hit.Tags, ",") + "]"
		}
		obj.Reasons = append(obj.Reasons, reason)
	}
}

// shouldScan determines if an object should be YARA-scanned.
func shouldScan(obj *types.ExecutionObject) bool {
	if !obj.Exists || obj.Path == "" {
		return false
	}

	// Skip System32 signed Microsoft files (performance)
	if obj.LocationType == "System32" && obj.Signed && obj.SignValid {
		return false
	}

	// Scan if: high risk, has triggers, has forensic hits, or is in user dir
	if obj.FinalScore >= 20 {
		return true
	}
	if obj.TriggerCount > 0 {
		return true
	}
	if obj.ForensicHits > 0 {
		return true
	}
	if obj.LocationType == "UserDir" || obj.LocationType == "Temp" || obj.LocationType == "ProgramData" {
		return true
	}
	if !obj.Signed {
		return true
	}

	return false
}

// isScannable checks if a file extension should be scanned.
func isScannable(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	scanExts := map[string]bool{
		".exe": true, ".dll": true, ".sys": true, ".scr": true, ".com": true,
		".ps1": true, ".vbs": true, ".js": true, ".hta": true,
		".bat": true, ".cmd": true, ".sct": true, ".wsf": true,
		".msi": true, ".pif": true,
	}
	return scanExts[ext]
}

// RuleCount returns the number of loaded rules.
func (e *Engine) RuleCount() int {
	if e == nil || e.ruleSet == nil {
		return 0
	}
	return len(e.ruleSet.Rules)
}

// Enabled returns whether the engine has rules loaded.
func (e *Engine) Enabled() bool {
	return e != nil && e.enabled && e.ruleSet != nil && len(e.ruleSet.Rules) > 0
}

// Errors returns any rule loading errors.
func (e *Engine) Errors() []string {
	if e == nil || e.ruleSet == nil {
		return nil
	}
	return e.ruleSet.Errors
}
