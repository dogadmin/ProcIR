package trigger

import (
	"fmt"

	"procir/internal/i18n"
	"procir/internal/types"

	"golang.org/x/sys/windows/registry"
)

// collectIFEO scans Image File Execution Options for Debugger hijacks.
func collectIFEO() []*types.TriggerEntry {
	var results []*types.TriggerEntry

	basePath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, basePath, registry.READ)
	if err != nil {
		return nil
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	for _, name := range subkeys {
		subkey, err := registry.OpenKey(registry.LOCAL_MACHINE, basePath+`\`+name, registry.READ)
		if err != nil {
			continue
		}

		debugger, _, err := subkey.GetStringValue("Debugger")
		subkey.Close()
		if err != nil || debugger == "" {
			continue
		}

		// Some legitimate debuggers exist (like vsjitdebugger), skip known ones
		// But for IR, we report all and let scoring handle it
		entry := &types.TriggerEntry{
			Type:        types.TriggerIFEO,
			Name:        name,
			Path:        extractExePath(debugger),
			CommandLine: debugger,
			Detail:      fmt.Sprintf(i18n.T("trig_ifeo_fmt"), name, truncate(debugger, 100)),
		}

		results = append(results, entry)
	}

	return results
}
