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

// collectRecentFiles scans user directories for recently created/modified executables and scripts.
func collectRecentFiles() []*types.ForensicEntry {
	var results []*types.ForensicEntry

	now := time.Now()
	cutoff72h := now.Add(-72 * time.Hour)

	scanDirs := []string{
		os.Getenv("USERPROFILE"),
		`C:\Users\Public`,
		`C:\ProgramData`,
		os.Getenv("TEMP"),
		`C:\Windows\Temp`,
	}

	// Also scan all user profiles
	userRoot := `C:\Users`
	if profiles, err := os.ReadDir(userRoot); err == nil {
		for _, p := range profiles {
			if !p.IsDir() {
				continue
			}
			name := strings.ToLower(p.Name())
			if name == "public" || name == "default" || name == "default user" || name == "all users" {
				continue
			}
			scanDirs = append(scanDirs,
				filepath.Join(userRoot, p.Name(), "Desktop"),
				filepath.Join(userRoot, p.Name(), "Downloads"),
				filepath.Join(userRoot, p.Name(), "Documents"),
				filepath.Join(userRoot, p.Name(), "AppData", "Local", "Temp"),
				filepath.Join(userRoot, p.Name(), "AppData", "Roaming"),
			)
		}
	}

	suspiciousExts := map[string]string{
		".exe": "exe", ".dll": "dll", ".sys": "dll",
		".bat": "script", ".cmd": "script", ".ps1": "script",
		".vbs": "script", ".js": "script", ".wsf": "script",
		".hta": "script", ".scr": "exe", ".com": "exe",
		".pif": "exe", ".msi": "exe",
	}

	seen := make(map[string]bool)

	for _, dir := range scanDirs {
		if dir == "" {
			continue
		}
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return filepath.SkipDir
			}
			if info.IsDir() {
				// Limit depth to avoid scanning too deep
				rel, _ := filepath.Rel(dir, path)
				if strings.Count(rel, string(filepath.Separator)) > 3 {
					return filepath.SkipDir
				}
				// Skip known-good heavy directories
				base := strings.ToLower(info.Name())
				if base == "node_modules" || base == ".git" || base == "cache" || base == "package cache" {
					return filepath.SkipDir
				}
				return nil
			}

			// Check if recently modified
			if info.ModTime().Before(cutoff72h) {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(info.Name()))
			fileType, isSuspicious := suspiciousExts[ext]
			if !isSuspicious {
				return nil
			}

			pathLower := strings.ToLower(path)
			if seen[pathLower] {
				return nil
			}
			seen[pathLower] = true

			age := now.Sub(info.ModTime())
			ageLabel := i18n.T("fore_72h")
			if age < 24*time.Hour {
				ageLabel = i18n.T("fore_24h")
			}

			fe := &types.ForensicEntry{
				Source:      types.ForensicRecentFile,
				Path:        path,
				FileModTime: info.ModTime().Format("2006-01-02 15:04:05"),
				FileSize:    info.Size(),
				FileType:    fileType,
				Detail:      fmt.Sprintf(i18n.T("fore_recent_mod"), ageLabel, info.Name(), fileType, info.Size()),
			}

			results = append(results, fe)
			return nil
		})
	}

	return results
}
