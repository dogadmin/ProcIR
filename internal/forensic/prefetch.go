package forensic

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"procir/internal/i18n"
	"procir/internal/types"
)

// collectPrefetch scans C:\Windows\Prefetch for execution history.
// Prefetch filenames encode the executable name: EXECUTABLE-XXXXXXXX.pf
// File timestamps provide first/last execution times.
func collectPrefetch() []*types.ForensicEntry {
	var results []*types.ForensicEntry

	prefetchDir := `C:\Windows\Prefetch`
	entries, err := os.ReadDir(prefetchDir)
	if err != nil {
		return nil
	}

	now := time.Now()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".pf") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Parse executable name from filename: NAME-XXXXXXXX.pf
		exeName := parsePrefetchName(name)
		if exeName == "" {
			continue
		}

		fullPath := filepath.Join(prefetchDir, name)
		modTime := info.ModTime()
		createTime := modTime // On NTFS, creation time is available but Go uses ModTime

		// Use file stat for creation time
		if stat, err := os.Stat(fullPath); err == nil {
			createTime = stat.ModTime()
		}

		age := now.Sub(modTime)
		ageLabel := ""
		if age < 24*time.Hour {
			ageLabel = i18n.T("fore_24h")
		} else if age < 72*time.Hour {
			ageLabel = i18n.T("fore_72h")
		} else if age < 7*24*time.Hour {
			ageLabel = i18n.T("fore_7d")
		}

		detail := fmt.Sprintf("Prefetch: %s", exeName)
		if ageLabel != "" {
			detail += fmt.Sprintf(i18n.T("fore_last_exec"), ageLabel)
		}

		fe := &types.ForensicEntry{
			Source:      types.ForensicPrefetch,
			Path:        fullPath,
			ExeName:     exeName,
			LastRunTime: modTime.Format("2006-01-02 15:04:05"),
			FirstSeen:   createTime.Format("2006-01-02 15:04:05"),
			FileSize:    info.Size(),
			Detail:      detail,
		}

		results = append(results, fe)
	}

	return results
}

// parsePrefetchName extracts the executable name from a prefetch filename.
// Format: EXECUTABLE_NAME-XXXXXXXX.pf
func parsePrefetchName(pfName string) string {
	// Remove .pf extension
	name := strings.TrimSuffix(pfName, ".pf")
	name = strings.TrimSuffix(name, ".PF")

	// Find last dash followed by 8 hex chars
	lastDash := strings.LastIndex(name, "-")
	if lastDash < 0 {
		return ""
	}

	hash := name[lastDash+1:]
	if len(hash) != 8 {
		return ""
	}

	return name[:lastDash]
}
