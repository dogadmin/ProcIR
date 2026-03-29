package event

import (
	"fmt"
	"strings"

	"procir/internal/i18n"
	"procir/internal/types"
)

// Correlate links EventEvidence entries to ExecutionObjects.
func Correlate(events []*types.EventEvidence, objects []*types.ExecutionObject) {
	// Build path index
	pathIndex := make(map[string]*types.ExecutionObject) // lowercase path → object
	for _, obj := range objects {
		if obj.Path != "" {
			pathIndex[strings.ToLower(obj.Path)] = obj
		}
	}

	for _, ev := range events {
		var linked *types.ExecutionObject

		// 1. Match by ProcessPath
		if ev.ProcessPath != "" {
			if obj, ok := pathIndex[strings.ToLower(ev.ProcessPath)]; ok {
				linked = obj
			}
		}

		// 2. Match by TargetPath
		if linked == nil && ev.TargetPath != "" {
			if obj, ok := pathIndex[strings.ToLower(ev.TargetPath)]; ok {
				linked = obj
			}
		}

		// 3. Match by partial path in CommandLine
		if linked == nil && ev.CommandLine != "" {
			cmdLower := strings.ToLower(ev.CommandLine)
			for path, obj := range pathIndex {
				if path != "" && len(path) > 10 && strings.Contains(cmdLower, path) {
					linked = obj
					break
				}
			}
		}

		// 4. Match by ServiceName / TaskName against trigger names
		if linked == nil && (ev.ServiceName != "" || ev.TaskName != "") {
			for _, obj := range objects {
				for _, t := range obj.Triggers {
					if ev.ServiceName != "" && strings.EqualFold(t.Name, ev.ServiceName) {
						linked = obj
						break
					}
					if ev.TaskName != "" && strings.EqualFold(t.Name, ev.TaskName) {
						linked = obj
						break
					}
				}
				if linked != nil {
					break
				}
			}
		}

		if linked != nil {
			ev.LinkedObject = linked.Path
			linked.Events = append(linked.Events, ev)
			linked.EventCount++

			// Update time bounds
			if linked.FirstEventTime == "" || ev.Time < linked.FirstEventTime {
				linked.FirstEventTime = ev.Time
			}
			if linked.LastEventTime == "" || ev.Time > linked.LastEventTime {
				linked.LastEventTime = ev.Time
			}

			// Accumulate event score (take max)
			if ev.Score > linked.EventScore {
				linked.EventScore = ev.Score
			}
		}
	}

	// Apply event scores to final scores
	for _, obj := range objects {
		if obj.EventCount == 0 {
			continue
		}

		obj.FinalScore += obj.EventScore
		obj.Reasons = append(obj.Reasons, eventSummary(obj))

		// Synergy: events + persistence
		if obj.TriggerCount > 0 && obj.EventScore >= 15 {
			obj.FinalScore += 20
			obj.Reasons = append(obj.Reasons, i18n.T("evtfusion_persist"))
		}

		// Synergy: events + YARA
		if obj.YaraMatched && obj.EventScore >= 15 {
			obj.FinalScore += 20
			obj.Reasons = append(obj.Reasons, i18n.T("evtfusion_yara"))
		}

		// Synergy: events + network
		if obj.NetworkObserved && obj.EventScore >= 10 {
			obj.FinalScore += 20
			obj.Reasons = append(obj.Reasons, i18n.T("evtfusion_net"))
		}

		// Synergy: multiple event types
		eventTypes := make(map[int]bool)
		for _, ev := range obj.Events {
			eventTypes[ev.EventID] = true
		}
		if len(eventTypes) >= 3 {
			obj.FinalScore += 15
			obj.Reasons = append(obj.Reasons, i18n.T("evtfusion_multitype"))
		}

		obj.RiskLevel = types.CalcRiskLevel(obj.FinalScore)
	}
}

func eventSummary(obj *types.ExecutionObject) string {
	if obj.EventCount == 1 {
		return i18n.T("evtfusion_1event")
	}
	return fmt.Sprintf(i18n.T("evtfusion_nevents"), obj.EventCount, obj.FirstEventTime, obj.LastEventTime)
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
