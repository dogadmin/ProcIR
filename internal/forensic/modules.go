package forensic

import (
	"fmt"
	"strings"
	"unsafe"

	"procir/internal/i18n"
	"procir/internal/signature"
	"procir/internal/types"

	"golang.org/x/sys/windows"
)

// collectModules enumerates loaded DLLs for all processes and flags suspicious ones.
func collectModules(pids []uint32) []*types.ForensicEntry {
	var results []*types.ForensicEntry

	// Known system DLL names that should only be in System32
	systemDLLs := map[string]bool{
		"ntdll.dll": true, "kernel32.dll": true, "kernelbase.dll": true,
		"advapi32.dll": true, "user32.dll": true, "gdi32.dll": true,
		"shell32.dll": true, "ole32.dll": true, "oleaut32.dll": true,
		"msvcrt.dll": true, "ws2_32.dll": true, "wininet.dll": true,
		"crypt32.dll": true, "secur32.dll": true, "rpcrt4.dll": true,
		"combase.dll": true, "shlwapi.dll": true, "urlmon.dll": true,
	}

	pidNames := make(map[uint32]string)
	seen := make(map[string]bool) // dedup by path

	for _, pid := range pids {
		if pid == 0 || pid == 4 {
			continue
		}

		modules := getProcessModules(pid)
		for _, modPath := range modules {
			pathLower := strings.ToLower(modPath)

			if seen[pathLower] {
				continue
			}

			suspicious := false
			var reasons []string

			modName := baseName(modPath)
			modNameLower := strings.ToLower(modName)

			// Check: user directory DLL
			if isUserDirPath(pathLower) {
				suspicious = true
				reasons = append(reasons, i18n.T("user_dir_dll"))
			}

			// Check: temp directory DLL
			if isTempDirPath(pathLower) {
				suspicious = true
				reasons = append(reasons, i18n.T("temp_dir_dll"))
			}

			// Check: system DLL name from non-system path
			if systemDLLs[modNameLower] && !isSystemPath(pathLower) {
				suspicious = true
				reasons = append(reasons, i18n.T("sysdll_masquerade"))
			}

			// Check: DLL in ProgramData
			if strings.HasPrefix(pathLower, `c:\programdata\`) {
				suspicious = true
				reasons = append(reasons, i18n.T("programdata_exec"))
			}

			if !suspicious {
				continue
			}

			seen[pathLower] = true

			// Check signature for suspicious DLLs
			sigInfo := signature.Analyze(modPath)

			if !sigInfo.Signed {
				reasons = append(reasons, i18n.T("fore_unsigned"))
			}

			processName := pidNames[pid]
			if processName == "" {
				processName = fmt.Sprintf("PID:%d", pid)
			}

			fe := &types.ForensicEntry{
				Source:       types.ForensicModule,
				Path:         modPath,
				ProcessPID:   pid,
				ProcessName:  processName,
				ModulePath:   modPath,
				ModuleSigned: sigInfo.Signed,
				ModuleSigner: sigInfo.Signer,
				Detail:       fmt.Sprintf(i18n.T("fore_susp_module"), modName, processName),
			}

			fe.Reasons = reasons
			results = append(results, fe)
		}
	}

	return results
}

func getProcessModules(pid uint32) []string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))

	err = windows.Module32First(snap, &me)
	if err != nil {
		return nil
	}

	var modules []string
	for {
		modPath := windows.UTF16ToString(me.ExePath[:])
		if modPath != "" {
			modules = append(modules, modPath)
		}

		err = windows.Module32Next(snap, &me)
		if err != nil {
			break
		}
	}

	// Skip first module (the exe itself), return only DLLs
	if len(modules) > 1 {
		return modules[1:]
	}
	return nil
}

func isUserDirPath(p string) bool {
	return strings.HasPrefix(p, `c:\users\`) &&
		!strings.Contains(p, `\appdata\local\microsoft\`) &&
		!strings.Contains(p, `\appdata\local\programs\`)
}

func isTempDirPath(p string) bool {
	return strings.Contains(p, `\temp\`) || strings.Contains(p, `\tmp\`)
}

func isSystemPath(p string) bool {
	return strings.HasPrefix(p, `c:\windows\system32`) ||
		strings.HasPrefix(p, `c:\windows\syswow64`) ||
		strings.HasPrefix(p, `c:\windows\winsxs`)
}
