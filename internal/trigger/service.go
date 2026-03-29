package trigger

import (
	"fmt"
	"strings"
	"unsafe"

	"procir/internal/i18n"
	"procir/internal/types"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// collectServices scans Windows services with detailed info.
func collectServices() []*types.TriggerEntry {
	var results []*types.TriggerEntry

	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil
	}
	defer windows.CloseServiceHandle(scm)

	var bytesNeeded, servicesReturned, resumeHandle uint32
	windows.EnumServicesStatusEx(
		scm, windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
		nil, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nil,
	)
	if bytesNeeded == 0 {
		return nil
	}

	buf := make([]byte, bytesNeeded)
	err = windows.EnumServicesStatusEx(
		scm, windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
		&buf[0], bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, nil,
	)
	if err != nil {
		return nil
	}

	type enumEntry struct {
		ServiceName *uint16
		DisplayName *uint16
		Status      windows.SERVICE_STATUS_PROCESS
	}
	entrySize := unsafe.Sizeof(enumEntry{})

	for i := uint32(0); i < servicesReturned; i++ {
		entry := (*enumEntry)(unsafe.Pointer(&buf[uintptr(i)*entrySize]))
		svcName := windows.UTF16PtrToString(entry.ServiceName)
		displayName := windows.UTF16PtrToString(entry.DisplayName)

		svcHandle, err := windows.OpenService(scm, entry.ServiceName, windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			continue
		}

		var needed uint32
		windows.QueryServiceConfig(svcHandle, nil, 0, &needed)
		if needed == 0 {
			windows.CloseServiceHandle(svcHandle)
			continue
		}

		cfgBuf := make([]byte, needed)
		cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&cfgBuf[0]))
		err = windows.QueryServiceConfig(svcHandle, cfg, needed, &needed)
		windows.CloseServiceHandle(svcHandle)
		if err != nil {
			continue
		}

		binaryPath := windows.UTF16PtrToString(cfg.BinaryPathName)
		account := windows.UTF16PtrToString(cfg.ServiceStartName)

		startType := "Unknown"
		switch cfg.StartType {
		case windows.SERVICE_AUTO_START:
			startType = "Auto"
		case windows.SERVICE_BOOT_START:
			startType = "Boot"
		case windows.SERVICE_DEMAND_START:
			startType = "Manual"
		case windows.SERVICE_DISABLED:
			startType = "Disabled"
		case windows.SERVICE_SYSTEM_START:
			startType = "System"
		}
		// Delayed auto-start uses Auto + flag, but we mark as Auto

		state := "Stopped"
		if entry.Status.CurrentState == windows.SERVICE_RUNNING {
			state = "Running"
		} else if entry.Status.CurrentState == windows.SERVICE_START_PENDING {
			state = "StartPending"
		} else if entry.Status.CurrentState == windows.SERVICE_STOP_PENDING {
			state = "StopPending"
		}

		// Check for ServiceDLL (svchost services)
		serviceDLL := getServiceDLL(svcName)

		exePath := extractExePath(binaryPath)

		te := &types.TriggerEntry{
			Type:             types.TriggerService,
			Name:             svcName,
			Path:             exePath,
			CommandLine:      binaryPath,
			Detail:           fmt.Sprintf(i18n.T("trig_svc_fmt"), svcName, displayName, startType, state),
			ServiceStartType: startType,
			ServiceAccount:   account,
			ServiceState:     state,
			ServiceDLL:       serviceDLL,
		}

		results = append(results, te)
	}

	return results
}

// getServiceDLL reads the ServiceDLL value for svchost-hosted services.
func getServiceDLL(serviceName string) string {
	keyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\%s\Parameters`, serviceName)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		// Try without Parameters
		keyPath = fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\%s`, serviceName)
		key, err = registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
		if err != nil {
			return ""
		}
	}
	defer key.Close()

	val, _, err := key.GetStringValue("ServiceDll")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(val)
}
