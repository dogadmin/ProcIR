package proctree

import (
	"os"
	"path/filepath"
	"strings"

	"procir/internal/i18n"
	"procir/internal/types"
)

// BuildTree constructs a process tree from process records.
func BuildTree(processes []*types.ProcessRecord) []*types.ProcessNode {
	nodeMap := make(map[uint32]*types.ProcessNode)
	for _, p := range processes {
		nodeMap[p.PID] = &types.ProcessNode{
			PID:   p.PID,
			PPID:  p.PPID,
			Name:  p.Name,
			Path:  p.Path,
			Score: p.RiskScore,
			Level: p.RiskLevel,
		}
	}

	// Link children to parents
	var roots []*types.ProcessNode
	for _, node := range nodeMap {
		parent, ok := nodeMap[node.PPID]
		if ok && parent != node {
			parent.Children = append(parent.Children, node)
		} else {
			roots = append(roots, node)
		}
	}

	return roots
}

// DetectDirClusters finds directories containing multiple suspicious files.
func DetectDirClusters(
	processes []*types.ProcessRecord,
	triggers []*types.TriggerEntry,
	forensics []*types.ForensicEntry,
) []*types.DirCluster {
	// Collect all suspicious file paths
	dirFiles := make(map[string]map[string]string) // dir → filename → type

	addFile := func(path string) {
		if path == "" {
			return
		}
		pathLower := strings.ToLower(path)

		// Only care about user/temp/programdata dirs
		if !strings.HasPrefix(pathLower, `c:\users\`) &&
			!strings.HasPrefix(pathLower, `c:\programdata\`) &&
			!strings.Contains(pathLower, `\temp\`) &&
			!strings.HasPrefix(pathLower, `c:\temp`) {
			return
		}

		dir := strings.ToLower(filepath.Dir(path))
		name := strings.ToLower(filepath.Base(path))
		ext := strings.ToLower(filepath.Ext(name))

		fileType := ""
		switch ext {
		case ".exe", ".scr", ".com":
			fileType = "exe"
		case ".dll", ".sys":
			fileType = "dll"
		case ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".wsf":
			fileType = "script"
		default:
			return
		}

		if dirFiles[dir] == nil {
			dirFiles[dir] = make(map[string]string)
		}
		dirFiles[dir][name] = fileType
	}

	// From processes
	for _, p := range processes {
		addFile(p.Path)
	}

	// From triggers
	for _, t := range triggers {
		addFile(t.Path)
	}

	// From forensics (recent files and modules)
	for _, f := range forensics {
		addFile(f.Path)
		addFile(f.ModulePath)
	}

	// Also scan directories that have suspicious files for more files
	for dir := range dirFiles {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			addFile(filepath.Join(dir, entry.Name()))
		}
	}

	// Build clusters
	var clusters []*types.DirCluster
	for dir, files := range dirFiles {
		if len(files) < 2 {
			continue
		}

		cluster := &types.DirCluster{
			Directory: dir,
			Count:     len(files),
		}

		typeSet := make(map[string]bool)
		for name, ft := range files {
			cluster.Files = append(cluster.Files, name)
			typeSet[ft] = true
		}
		for ft := range typeSet {
			cluster.FileTypes = append(cluster.FileTypes, ft)
		}

		// Scoring
		if len(files) >= 3 {
			cluster.Score = 25
			cluster.Reasons = append(cluster.Reasons, i18n.T("tree_dir_3plus_suspicious"))
		} else {
			cluster.Score = 15
			cluster.Reasons = append(cluster.Reasons, i18n.T("tree_dir_2_suspicious"))
		}

		// Extra score for mixed types (exe+dll = classic sideload)
		if typeSet["exe"] && typeSet["dll"] {
			cluster.Score += 10
			cluster.Reasons = append(cluster.Reasons, i18n.T("tree_exe_dll_sideload"))
		}
		if typeSet["script"] {
			cluster.Score += 5
			cluster.Reasons = append(cluster.Reasons, i18n.T("tree_has_script"))
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}
