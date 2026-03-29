package trigger

import (
	"fmt"
	"strings"

	"procir/internal/i18n"
	"procir/internal/types"

	"golang.org/x/sys/windows/registry"
)

// collectWinlogon scans Winlogon Shell and Userinit for hijacks.
func collectWinlogon() []*types.TriggerEntry {
	var results []*types.TriggerEntry

	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.READ)
	if err != nil {
		return nil
	}
	defer key.Close()

	// Check Shell (default: explorer.exe)
	shell, _, err := key.GetStringValue("Shell")
	if err == nil && shell != "" {
		shellLower := strings.ToLower(strings.TrimSpace(shell))
		// Only flag if it's not the default explorer.exe
		if shellLower != "explorer.exe" {
			entry := &types.TriggerEntry{
				Type:        types.TriggerWinlogon,
				Name:        "Winlogon\\Shell",
				Path:        extractExePath(shell),
				CommandLine: shell,
				Detail:      fmt.Sprintf(i18n.T("trig_winlogon_shell"), shell),
			}
			results = append(results, entry)
		}
	}

	// Check Userinit (default: C:\Windows\system32\userinit.exe,)
	userinit, _, err := key.GetStringValue("Userinit")
	if err == nil && userinit != "" {
		// Default value contains userinit.exe with trailing comma
		lower := strings.ToLower(strings.TrimSpace(userinit))
		isDefault := lower == `c:\windows\system32\userinit.exe,` ||
			lower == `c:\windows\system32\userinit.exe`

		if !isDefault {
			// Check if there are extra entries appended
			parts := strings.Split(userinit, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				partLower := strings.ToLower(part)
				if strings.Contains(partLower, "userinit.exe") {
					continue // skip the legit one
				}

				entry := &types.TriggerEntry{
					Type:        types.TriggerWinlogon,
					Name:        "Winlogon\\Userinit",
					Path:        extractExePath(part),
					CommandLine: part,
					Detail:      fmt.Sprintf(i18n.T("trig_winlogon_userinit_a"), part),
				}
				results = append(results, entry)
			}

			// If no extra parts but value is different, flag the whole thing
			if len(results) == 0 {
				entry := &types.TriggerEntry{
					Type:        types.TriggerWinlogon,
					Name:        "Winlogon\\Userinit",
					Path:        extractExePath(userinit),
					CommandLine: userinit,
					Detail:      fmt.Sprintf(i18n.T("trig_winlogon_userinit_m"), userinit),
				}
				results = append(results, entry)
			}
		}
	}

	return results
}
