package trigger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"procir/internal/i18n"
	"procir/internal/types"
)

// collectTasks scans Windows Scheduled Tasks with detailed field extraction.
func collectTasks() []*types.TriggerEntry {
	var results []*types.TriggerEntry

	taskRoot := `C:\Windows\System32\Tasks`

	filepath.Walk(taskRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)

		// Skip non-XML files
		if !strings.Contains(content, "<Task") {
			return nil
		}

		taskName := strings.TrimPrefix(path, taskRoot)
		taskName = strings.ReplaceAll(taskName, `\`, "/")

		// Extract fields from XML
		author := xmlTag(content, "Author")
		description := xmlTag(content, "Description")
		runAs := xmlTag(content, "UserId")
		if runAs == "" {
			runAs = xmlTag(content, "Principal")
		}
		hidden := strings.Contains(content, "<Hidden>true</Hidden>")

		// Determine trigger type
		triggerType := "unknown"
		if strings.Contains(content, "<LogonTrigger") {
			triggerType = "logon"
		} else if strings.Contains(content, "<TimeTrigger") || strings.Contains(content, "<CalendarTrigger") {
			triggerType = "time"
		} else if strings.Contains(content, "<BootTrigger") {
			triggerType = "boot"
		} else if strings.Contains(content, "<IdleTrigger") {
			triggerType = "idle"
		} else if strings.Contains(content, "<EventTrigger") {
			triggerType = "event"
		} else if strings.Contains(content, "<RegistrationTrigger") {
			triggerType = "registration"
		}

		// Extract repetition interval
		interval := xmlTag(content, "Interval")

		// Extract all Actions (can have multiple Exec actions)
		actions := extractActions(content)
		if len(actions) == 0 {
			return nil
		}

		for _, action := range actions {
			entry := &types.TriggerEntry{
				Type:            types.TriggerTask,
				Name:            taskName,
				Path:            action.path,
				CommandLine:     action.cmdline,
				Detail:          fmt.Sprintf(i18n.T("trig_task_fmt"), taskName, truncate(action.cmdline, 100)),
				TaskAuthor:      author,
				TaskDescription: description,
				TaskTriggerType: triggerType,
				TaskRunAs:       runAs,
				TaskHidden:      hidden,
				TaskInterval:    interval,
			}

			results = append(results, entry)
		}

		return nil
	})

	return results
}

type taskAction struct {
	path    string
	cmdline string
}

func extractActions(xml string) []taskAction {
	var actions []taskAction

	remaining := xml
	for {
		execIdx := strings.Index(remaining, "<Exec>")
		if execIdx < 0 {
			execIdx = strings.Index(remaining, "<Exec ")
		}
		if execIdx < 0 {
			break
		}
		remaining = remaining[execIdx:]

		endIdx := strings.Index(remaining, "</Exec>")
		if endIdx < 0 {
			break
		}
		block := remaining[:endIdx]
		remaining = remaining[endIdx+7:]

		command := xmlTag(block, "Command")
		args := xmlTag(block, "Arguments")
		workDir := xmlTag(block, "WorkingDirectory")

		if command == "" {
			continue
		}

		fullCmd := command
		if args != "" {
			fullCmd += " " + args
		}

		path := extractExePath(command)
		_ = workDir

		actions = append(actions, taskAction{
			path:    path,
			cmdline: fullCmd,
		})
	}

	return actions
}

// xmlTag extracts the text content of a simple XML tag.
func xmlTag(xml, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"

	idx := strings.Index(xml, open)
	if idx < 0 {
		return ""
	}
	start := idx + len(open)
	end := strings.Index(xml[start:], close)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(xml[start : start+end])
}
