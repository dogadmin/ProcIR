package trigger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"procir/internal/i18n"
	"procir/internal/types"
)

// collectStartup scans Startup folders for auto-run entries.
func collectStartup() []*types.TriggerEntry {
	var results []*types.TriggerEntry

	dirs := []struct {
		path  string
		label string
	}{
		{filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`), i18n.T("trig_startup_user")},
		{`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`, i18n.T("trig_startup_system")},
	}

	for _, d := range dirs {
		entries, err := os.ReadDir(d.path)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext != ".lnk" && ext != ".exe" && ext != ".bat" && ext != ".cmd" &&
				ext != ".vbs" && ext != ".js" && ext != ".ps1" && ext != ".url" {
				continue
			}

			fullPath := filepath.Join(d.path, entry.Name())

			te := &types.TriggerEntry{
				Type:        types.TriggerStartup,
				Name:        entry.Name(),
				Path:        fullPath,
				CommandLine: fullPath,
				Detail:      fmt.Sprintf("%s\\%s", d.label, entry.Name()),
			}

			// For .lnk files, the actual target needs COM to resolve
			// For now, record the .lnk path itself
			if ext == ".lnk" {
				te.Detail += i18n.T("trig_shortcut")
			}

			results = append(results, te)
		}
	}

	return results
}
