package scoring

import (
	"sort"
	"strings"
	"sync"

	"procir/internal/behavior"
	"procir/internal/i18n"
	ctx "procir/internal/context"
	"procir/internal/event"
	"procir/internal/file"
	"procir/internal/forensic"
	"procir/internal/fusion"
	"procir/internal/indicator"
	"procir/internal/module"
	"procir/internal/network"
	"procir/internal/persistence"
	"procir/internal/process"
	"procir/internal/proctree"
	"procir/internal/rules"
	"procir/internal/signature"
	"procir/internal/timeline"
	"procir/internal/trigger"
	"procir/internal/types"
	"procir/internal/yara"
)

// YaraEngine is the shared YARA engine instance.
var YaraEngine *yara.Engine

// ScanResult holds the complete scan output.
type ScanResult struct {
	Records      []*types.ProcessRecord
	Triggers     []*types.TriggerEntry
	Forensics    []*types.ForensicEntry
	EventResults    []*types.EventEvidence
	ModuleAnalyses  []*types.ModuleAnalysis
	ExecObjects     []*types.ExecutionObject
	Correlation  *types.CorrelationResult
	YaraLoaded   bool
	YaraRules    int
}

// Scan performs a full system scan and returns scored results.
func Scan(progressFn func(current, total int)) *ScanResult {
	// Step 1: Collect processes
	processes := process.Collect()

	pidMap := make(map[uint32]string)
	for _, p := range processes {
		pidMap[p.PID] = p.Name
	}

	// Step 2: Initialize analyzers
	fileAnalyzer := file.NewAnalyzer()
	netAnalyzer := network.NewAnalyzer()
	persAnalyzer := persistence.NewAnalyzer()

	// Step 3: Analyze each process concurrently
	total := len(processes)
	records := make([]*types.ProcessRecord, total)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for i, p := range processes {
		wg.Add(1)
		go func(idx int, proc process.ProcessInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rec := &types.ProcessRecord{
				PID:         proc.PID,
				PPID:        proc.PPID,
				Name:        proc.Name,
				Path:        proc.Path,
				CommandLine: proc.CommandLine,
				User:        proc.User,
				StartTime:   proc.StartTime,
				ParentName:  pidMap[proc.PPID],
			}

			fi := fileAnalyzer.Analyze(proc.Path)
			rec.FileExists = fi.Exists
			rec.FileSize = fi.Size
			rec.FileModTime = fi.ModTime
			rec.SHA256 = fi.SHA256
			rec.MD5 = fi.MD5

			if proc.Path != "" && fi.Exists {
				sig := signature.Analyze(proc.Path)
				rec.Signed = sig.Signed
				rec.SignValid = sig.SignValid
				rec.Signer = sig.Signer
				rec.Company = sig.Company
				rec.Product = sig.Product
				rec.OriginalName = sig.OriginalName
				rec.FileVersion = sig.FileVersion
			}

			if rec.OriginalName != "" {
				origLower := strings.ToLower(rec.OriginalName)
				nameLower := strings.ToLower(proc.Name)
				if origLower != nameLower {
					rec.OriginalNameMismatch = true
				}
			}

			ctxResult := ctx.Analyze(proc.Name, proc.Path, pidMap[proc.PPID])
			rec.IsLOLBin = ctxResult.IsLOLBin
			rec.PathAbnormal = ctxResult.PathAbnormal
			rec.IsMasquerade = ctxResult.IsMasquerade
			rec.AbnormalParentChain = ctxResult.AbnormalParentChain

			netResult := netAnalyzer.GetByPID(proc.PID)
			rec.HasNetwork = netResult.HasNetwork
			rec.RemoteIPs = netResult.RemoteIPs
			rec.RemotePorts = netResult.RemotePorts
			rec.HasPublicIP = netResult.HasPublicIP

			persResult := persAnalyzer.GetByPath(proc.Path)
			rec.Persistence = persResult.Mechanisms

			rules.Apply(rec)

			records[idx] = rec

			if progressFn != nil {
				progressFn(idx+1, total)
			}
		}(i, p)
	}

	wg.Wait()

	sort.Slice(records, func(i, j int) bool {
		return records[i].RiskScore > records[j].RiskScore
	})

	// Step 4: Collect triggers
	triggerResult := trigger.CollectAll()
	trigger.ScoreAll(triggerResult.Entries)

	sort.Slice(triggerResult.Entries, func(i, j int) bool {
		return triggerResult.Entries[i].Score > triggerResult.Entries[j].Score
	})

	// Step 5: Collect forensic artifacts
	var pids []uint32
	for _, r := range records {
		pids = append(pids, r.PID)
	}
	forensicResult := forensic.CollectAll(pids)

	// Step 6: Fuse into ExecutionObjects
	execObjects := fusion.Fuse(records, triggerResult.Entries, forensicResult.Entries)

	// Step 7: Event evidence collection (phase 6)
	eventResult := event.CollectAll(nil)
	event.ScoreAll(eventResult.Events)

	// Step 8: Event correlation with ExecutionObjects
	event.Correlate(eventResult.Events, execObjects)

	// Step 9: Correlation analysis (phase 4)
	tl := timeline.Build(records, triggerResult.Entries, forensicResult.Entries)
	// Add event evidence to timeline
	for _, ev := range eventResult.Events {
		if ev.Time != "" {
			tl = append(tl, &types.TimelineEvent{
				Time:       ev.Time,
				Type:       "eventlog",
				ObjectPath: firstNonEmpty(ev.ProcessPath, ev.TargetPath),
				ObjectName: ev.Description,
				Detail:     ev.Description,
				Score:      ev.Score,
				Source:     ev.Source,
			})
		}
	}
	// Re-sort timeline
	sort.SliceStable(tl, func(i, j int) bool { return tl[i].Time > tl[j].Time })

	chains := behavior.Detect(records, triggerResult.Entries, forensicResult.Entries)
	iocs := indicator.Extract(records, triggerResult.Entries, forensicResult.Entries)
	// Also extract IOCs from events
	for _, ev := range eventResult.Events {
		if ev.CommandLine != "" {
			// Re-use existing extraction
			iocs = append(iocs, extractEventIOCs(ev)...)
		}
	}
	tree := proctree.BuildTree(records)
	dirClusters := proctree.DetectDirClusters(records, triggerResult.Entries, forensicResult.Entries)

	// Step 10: Module abuse analysis (DLL sideload / 白加黑)
	moduleResult := module.AnalyzeAll(records)
	module.ApplyToObjects(moduleResult.Analyses, execObjects)

	// Step 11: Apply behavior chain scores into ExecObjects
	applyChainScores(execObjects, chains)
	applyDirClusterScores(execObjects, dirClusters)

	// Step 12: YARA scanning (if rules loaded)
	yaraLoaded := false
	yaraRules := 0
	if YaraEngine != nil && YaraEngine.Enabled() {
		YaraEngine.ScanObjects(execObjects)
		yaraLoaded = true
		yaraRules = YaraEngine.RuleCount()
	}

	// Re-sort after all scoring
	sort.Slice(execObjects, func(i, j int) bool {
		return execObjects[i].FinalScore > execObjects[j].FinalScore
	})

	return &ScanResult{
		Records:      records,
		Triggers:     triggerResult.Entries,
		Forensics:    forensicResult.Entries,
		EventResults:   eventResult.Events,
		ModuleAnalyses: moduleResult.Analyses,
		ExecObjects:    execObjects,
		Correlation: &types.CorrelationResult{
			Timeline:    tl,
			Chains:      chains,
			Indicators:  iocs,
			ProcessTree: tree,
			DirClusters: dirClusters,
		},
		YaraLoaded: yaraLoaded,
		YaraRules:  yaraRules,
	}
}

// applyChainScores adds behavior chain scores to matched ExecutionObjects.
func applyChainScores(objects []*types.ExecutionObject, chains []*types.BehaviorChain) {
	pathMap := make(map[string]*types.ExecutionObject)
	for _, obj := range objects {
		pathMap[strings.ToLower(obj.Path)] = obj
	}

	for _, chain := range chains {
		for _, objPath := range chain.ObjectPaths {
			key := strings.ToLower(objPath)
			if obj, ok := pathMap[key]; ok {
				obj.FinalScore += chain.PatternScore
				obj.Reasons = append(obj.Reasons, i18n.T("scan_behavior_chain")+chain.PatternName)
				obj.RiskLevel = types.CalcRiskLevel(obj.FinalScore)
			}
		}
	}
}

// applyDirClusterScores adds directory cluster scores to matched objects.
func applyDirClusterScores(objects []*types.ExecutionObject, clusters []*types.DirCluster) {
	for _, obj := range objects {
		pathLower := strings.ToLower(obj.Path)
		for _, cluster := range clusters {
			if strings.HasPrefix(pathLower, cluster.Directory+`\`) || strings.HasPrefix(pathLower, cluster.Directory+"/") {
				obj.FinalScore += cluster.Score
				obj.Reasons = append(obj.Reasons, i18n.T("scan_dir_cluster")+strings.Join(cluster.Reasons, "+"))
				obj.RiskLevel = types.CalcRiskLevel(obj.FinalScore)
				break
			}
		}
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" { return v }
	}
	return ""
}

// extractEventIOCs extracts IOCs from event evidence command lines.
func extractEventIOCs(ev *types.EventEvidence) []*types.Indicator {
	// Lightweight extraction — just URLs and IPs from event command lines
	var results []*types.Indicator
	cmd := ev.CommandLine
	if cmd == "" { return nil }

	source := ev.Source + ":" + ev.Description

	// Extract URLs
	for _, match := range strings.Fields(cmd) {
		if strings.HasPrefix(match, "http://") || strings.HasPrefix(match, "https://") {
			results = append(results, &types.Indicator{
				Type: "url", Value: match, SourceObject: source, Context: i18n.T("scan_event_log"),
			})
		}
	}

	return results
}
