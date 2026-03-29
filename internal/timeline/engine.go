package timeline

import (
	"sort"
	"strings"

	"procir/internal/i18n"
	"procir/internal/types"
)

// Build constructs a unified timeline from all data sources.
func Build(
	processes []*types.ProcessRecord,
	triggers []*types.TriggerEntry,
	forensics []*types.ForensicEntry,
) []*types.TimelineEvent {
	var events []*types.TimelineEvent

	// Process start times
	for _, p := range processes {
		if p.StartTime == "" {
			continue
		}
		events = append(events, &types.TimelineEvent{
			Time:       p.StartTime,
			Type:       "execution",
			ObjectPath: p.Path,
			ObjectName: p.Name,
			Detail:     formatProcDetail(p),
			Score:      p.RiskScore,
			Source:     "process",
		})
	}

	// Trigger-derived events
	for _, t := range triggers {
		// Tasks have LastRun / NextRun
		if t.TaskLastRun != "" {
			events = append(events, &types.TimelineEvent{
				Time:       t.TaskLastRun,
				Type:       "trigger",
				ObjectPath: t.Path,
				ObjectName: t.Name,
				Detail:     i18n.T("tl_task_last_exec") + t.Name,
				Score:      t.Score,
				Source:     string(t.Type),
			})
		}
	}

	// Forensic events
	for _, f := range forensics {
		timeStr := ""
		evtType := "file"

		switch f.Source {
		case types.ForensicPrefetch:
			timeStr = f.LastRunTime
			evtType = "execution"
		case types.ForensicEventLog:
			timeStr = f.EventTime
			evtType = "eventlog"
		case types.ForensicRecentFile:
			timeStr = f.FileModTime
			evtType = "file"
		case types.ForensicModule:
			evtType = "module"
			// Modules don't have timestamps; skip
			continue
		}

		if timeStr == "" {
			continue
		}

		events = append(events, &types.TimelineEvent{
			Time:       timeStr,
			Type:       evtType,
			ObjectPath: f.Path,
			ObjectName: baseName(f.Path),
			Detail:     f.Detail,
			Score:      f.Score,
			Source:     string(f.Source),
		})
	}

	// Sort by time descending (newest first)
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Time > events[j].Time
	})

	return events
}

func formatProcDetail(p *types.ProcessRecord) string {
	detail := p.Name + " (PID:" + itoa(int(p.PID)) + ")"
	if p.ParentName != "" {
		detail += " ← " + p.ParentName
	}
	if p.RiskScore > 0 {
		detail += " [" + p.RiskLevel + ":" + itoa(p.RiskScore) + "]"
	}
	return detail
}

func baseName(path string) string {
	if idx := strings.LastIndex(path, `\`); idx >= 0 {
		return path[idx+1:]
	}
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
