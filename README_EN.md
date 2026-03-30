[中文](README.md) | **English**

# ProcIR - Windows Incident Response Process Scanner

[![GitHub Release](https://img.shields.io/github/v/release/dogadmin/ProcIR)](https://github.com/dogadmin/ProcIR/releases/latest)

> A one-click incident response tool for security engineers to rapidly identify trojans, backdoors, persistence mechanisms, DLL sideloading, memory injection, and other threats.

> **Note:** ProcIR supports a bilingual (Chinese/English) UI with a toggle button to switch between languages.

---

## Purpose

ProcIR is a **non-resident, agentless, fully local** Windows incident response investigation tool.

Design scenario: You receive an incident response assignment and need to determine the following as quickly as possible after accessing the machine:

- Which processes are suspicious?
- Are there persistent backdoors?
- Is there DLL sideloading / DLL hijacking?
- Are there historical execution traces?
- What does the attack chain look like?

The traditional approach involves manually running a series of commands (tasklist, netstat, autoruns, schtasks...) and comparing results one by one — time-consuming and labor-intensive. ProcIR automates all of this: a single scan provides full-dimensional analysis, sorted by risk, telling you exactly where to look.

**Core philosophy: Not an antivirus, no kill capability — only discovery and analysis assistance.**

---

## Features

- **Single-file executable**, no installation required, no external dependencies, 11MB
- **Pure Go implementation**, no CGO, copy-and-run
- **Non-resident**, exits after scanning, no impact on production
- **No network required** for core analysis — all scanning is performed locally (AI analysis requires API access)
- **Dual-mode operation**: Embedded Web UI (GUI) + pure command-line mode (CLI) with JSON/CSV export
- **13 Analysis Views**, covering the full attack surface from processes to memory
- **AI-Powered Analysis**: Claude API (English) / MiniMax (Chinese) for intelligent threat assessment
- **Full bilingual support** — UI, 400+ detection rules, risk reasons, behavior chains, and all backend output fully translated in both Chinese and English

---

## Quick Start

### GUI Mode (Default)

```
# Run directly — browser opens automatically
procir.exe

# With YARA rules
procir.exe -yara rules.yar
procir.exe -yara C:\yara-rules\
```

After launching, the browser opens automatically. Click "Start Scan" and wait a few seconds for results.

### CLI Mode (Pure Command Line)

No GUI required — scan and export data directly. Ideal for automation scripts, remote SSH sessions, or headless environments.

```bash
# Scan and export as JSON (default format)
procir.exe -cli -o result.json

# Scan and export as CSV
procir.exe -cli -o result.csv -format csv

# Scan with YARA rules, export full results
procir.exe -cli -yara ./rules -o scan.json

# Export only YARA-matched results
procir.exe -cli -yara ./rules -yara-export -o yara_hits.json

# Auto-generate timestamped filename
procir.exe -cli
```

**CLI Flags:**

| Flag | Description |
|------|-------------|
| `-cli` | Enable CLI mode (no GUI) |
| `-o <path>` | Output file path |
| `-format json\|csv` | Export format, default json |
| `-yara <path>` | YARA rules file or directory |
| `-yara-export` | Export only YARA-matched results |

**Export Content:**

- **JSON full export**: ExecObjects, Processes, Triggers, Forensics, Events, Modules, Timeline, BehaviorChains, Indicators + Summary statistics
- **CSV full export**: ExecObjects with 27 key columns (including YARA columns)
- **YARA-only export**: Only YARA-matched objects with rule names, tags, and match scores

---

## Analysis Capabilities Overview

ProcIR analyzes system state across **9 Dimensions**, covering every stage of the attack lifecycle:

```
┌──────────────────────────────────────────────────────────┐
│  Execution Plane                                         │
│  All active processes → cmdline/parent-child/sig/net/    │
│  persistence                                             │
├──────────────────────────────────────────────────────────┤
│  Trigger Plane                                           │
│  Registry Run → Startup → Scheduled Tasks → Services →   │
│  WMI → IFEO                                              │
├──────────────────────────────────────────────────────────┤
│  Forensic Plane                                          │
│  Prefetch → Recent file modifications → Event logs →     │
│  DLL modules                                             │
├──────────────────────────────────────────────────────────┤
│  Event Plane                                             │
│  Security → System → PowerShell → TaskScheduler → Sysmon │
├──────────────────────────────────────────────────────────┤
│  Module Plane                                            │
│  DLL Sideload → Living-off-the-Land binaries → System    │
│  DLL impersonation → Same-directory loading              │
├──────────────────────────────────────────────────────────┤
│  YARA Plane                                              │
│  Pure Go YARA engine → Custom rules → File content       │
│  matching                                                │
├──────────────────────────────────────────────────────────┤
│  Memory Plane                                            │
│  Specify PID → VirtualQueryEx → RWX / Private executable │
│  / Fileless injection                                    │
├──────────────────────────────────────────────────────────┤
│  IOC Monitor                                             │
│  IP IOC → TCP connection table polling → Real-time hits  │
│  → Process attribution                                   │
├──────────────────────────────────────────────────────────┤
│  AI Analysis                                             │
│  Claude (EN) / MiniMax (CN) → One-click scan data feed   │
│  → Multi-turn conversation analysis                      │
└──────────────────────────────────────────────────────────┘
                         ↓
              Fusion Engine
              → ExecutionObject unified model
              → Multi-dimensional stacked scoring
              → Behavior chain identification
              → Timeline reconstruction
              → IOC auto-extraction
```

---

## 13 Analysis Views

| View | Function |
|------|----------|
| **Active Processes** | All running processes, sorted by risk score, with command line / signature / network / persistence at a glance |
| **Triggers** | All persistence entry points (Run/Task/Service/WMI/IFEO/Winlogon), independently scored |
| **Execution Objects** | Core view: processes + triggers + forensics + events + modules + YARA multi-dimensional fusion, unified scoring |
| **Historical Forensics** | Prefetch execution records, recent file modifications, event logs, suspicious modules |
| **Event Logs** | Security/System/PowerShell/TaskScheduler/WMI/Sysmon high-value events |
| **Module Analysis** | DLL hijack detection: sideloading / same-directory loading / system DLL name impersonation |
| **Timeline** | All events sorted chronologically to reconstruct the attack path |
| **Behavior Chains** | Automatic attack pattern identification: macro attack chains / browser exploitation chains / WMI backdoor chains / download-and-execute chains |
| **IOC** | Automatic extraction of URLs / IPs / domains / Base64 from command lines / triggers / events |
| **YARA** | Dedicated page: upload rules → full scan → hit results → rule details |
| **Memory Analysis** | Deep analysis by PID: RWX memory / private executable memory / non-image executable regions |
| **IOC Monitor** | Input IP/domain list → real-time TCP connection monitoring → hit alerts + process attribution |
| **AI Analysis** | Integrated Claude API (English) / MiniMax (Chinese), one-click scan data submission, multi-turn intelligent analysis |

---

## Scoring Model

ProcIR's scoring is not simple rule matching — it is a **multi-layer fusion model**:

### Layer 1: Base Rules (Each dimension scored independently)

```
Process Score = Signature(±8) + Path(±10~20) + Impersonation(+30) + Parent-Child Chain(+10~25)
             + Command Line(+20~30) + Network(+10~20) + Persistence(+20~25)
             → Strong Rule Override → Combination Weighted Synergy → White Feature Anti-FP → Context Weight(×1.2~1.5)

Trigger Score = Base(+15~30) + Path(+20) + Command Line(+20~30) + Task Features(+10) + Service Features(+10~25)

Event Score = EventID Weight(+5~30) + Command Line Detection(+15~20) + LOLBin Identification(+15)

Module Score = Unsigned(+20) + User Directory(+25) + System DLL Impersonation(+30) + Sideloading(+40) + Same Directory(+35) + System Process Anomaly(+50)

YARA Score = Per Rule(+20) + High-Risk Tags(+30) + Multi-Rule(+15) + Network Linkage(+20) + Persistence Linkage(+15)
```

### Layer 2: Fusion Scoring

```
FinalScore = ExecutionScore + TriggerScore + ForensicScore + EventScore
           + DLLHijackScore + YaraScore
           + BehaviorChainScore + DirClusterScore
           + SynergyBonus - WhiteReduction
```

### Layer 3: Fusion Rules

| Rule | Score |
|------|-------|
| Not running but trigger is high-risk | At least Medium(40) |
| Trigger contains encoded PowerShell execution | At least Critical(80) |
| User directory + auto-start | +20 |
| Running + outbound connection + persistence | +20 |
| 3+ trigger types pointing to the same object | At least Critical(80) |
| Historical execution + persistence | +20 |
| Event evidence + persistence | +20 |
| Event evidence + YARA hit | +20 |
| DLL hijack + outbound connection | +20 |

### Risk Levels

| Score | Level | Meaning |
|-------|-------|---------|
| 0-19 | Low | Essentially normal, can be ignored |
| 20-39 | Suspicious | Warrants attention |
| 40-59 | Medium | Recommended for focused investigation |
| 60-79 | High | Priority remediation |
| 80+ | Critical | Immediate response required |

---

## Detection Coverage

| Threat Type | Detection Method |
|-------------|------------------|
| LOLBin Abuse | 40+ LOLBin list + deep command line matching |
| DLL Sideloading / Hijacking | Signed process + unsigned DLL / same-directory loading / system DLL name impersonation |
| Office Macro Attacks | Parent-child process chain (Office → script engine) |
| PowerShell Attacks | -enc / hidden window / download / IEX + 4104 script logs |
| Persistence Backdoors | Run/RunOnce/Startup/Scheduled Tasks/Services/WMI/IFEO/Winlogon |
| WMI Persistence | EventFilter + Consumer + Binding full chain |
| System File Impersonation | 14 system process names + legitimate path comparison |
| Intermittent Execution / Timed Backdoors | Prefetch + Scheduled Tasks + Event Log cross-correlation |
| Cleaned Samples | Prefetch remnants + Event Logs (4688/7045/4698) |
| Memory Injection / Fileless | VirtualQueryEx enumerating RWX / private executable memory |
| C2 Communication | TCP connection table + IOC real-time monitoring |
| Lateral Movement Traces | 4624 (network logon) / 4648 (explicit credentials) / 4672 (privileged logon) |
| Privilege Escalation | 7045 (service installation) + LOLBin escalation commands |

---

## Behavior Chain Auto-Identification

ProcIR does not just perform point detections — it automatically identifies complete attack chains:

| Attack Chain | Detection Pattern | Score |
|-------------|-------------------|-------|
| Macro Attack Chain | Office → Script Engine (+ -enc/download) | +25~40 |
| Browser Exploitation Chain | Browser → System Tool (excluding Native Messaging) | +20 |
| Persistence Execution Chain | File drop + RunKey/Task + Prefetch execution record | +15~20 |
| WMI Backdoor Chain | WMI Consumer → Script Engine → URL/Encoding | +30 |
| DLL Sideloading Chain | Process loads unsigned DLL from user directory | +25 |
| Download-and-Execute Chain | cmd /c + curl/certutil + execution / PS download+IEX | +25~30 |

---

## YARA Integration

ProcIR includes a **pure Go YARA-compatible engine** (no CGO/GCC required), supporting:

- Text string matching (nocase / wide / ascii / fullword)
- Hex patterns (including `??` wildcards)
- Regular expressions
- Condition syntax (any of them / all of them / N of / boolean combinations / filesize)
- meta / tags

**Usage:**

1. Switch to the "YARA" tab
2. Click "Choose Rule File" to upload a `.yar` file, or enter a local path to load
3. Click "Scan All Objects"
4. Review hit results

Only suspicious objects are scanned (high score / user directory / unsigned / has triggers), automatically skipping signed system files.

---

## IOC Monitor

Real-time monitoring for communication with malicious IPs:

1. Switch to the "IOC Monitor" tab
2. Enter the IOC list (one IP or domain per line)
3. Set the monitoring duration, click "Start Monitoring"
4. Hits are displayed in real-time with process name / path / user / port

```
# IOC format
1.2.3.4
evil.com
1.2.3.4,high,intel_feed,C2 server
```

Domain IOCs are automatically resolved to IPs when loaded. During monitoring, only the kernel TCP connection table is read — **zero network impact**.

---

## AI-Powered Analysis

ProcIR integrates AI large language models for intelligent analysis of scan results:

- **English mode:** Claude API for analysis and threat assessment
- **Chinese mode:** MiniMax for analysis and threat assessment

### How to use:

1. Switch to the "AI Analysis" tab
2. Enter your API Key (Claude API Key for English mode, MiniMax API Key for Chinese mode; optionally check "Remember Key" to save locally)
3. Select a model
4. Click "Send Scan Data" to submit the complete scan results to AI in one click, or click "Send Summary" for a condensed version
5. You can also type questions directly in the input box for multi-turn conversation

**Key Features:**

- **One-click data feed**: Automatically formats and sends all scan data to AI — high-risk processes, suspicious triggers, behavior chains, IOCs, high-risk execution objects, suspicious modules, historical forensics, and high-risk events
- **Multi-turn conversation**: Supports contextual follow-up questions for deeper analysis
- **Professional prompt**: Built-in Windows incident response expert persona — AI delivers conclusions and remediation recommendations directly
- **Token statistics**: Real-time display of per-turn and cumulative token consumption
- **Local API Key storage**: Optionally store the key in browser localStorage

> Claude API Key: available at console.anthropic.com
> MiniMax API Key: available at platform.minimax.io

---

## Memory Analysis

Deep memory-level inspection of suspicious processes:

1. Identify a suspicious process in the "Active Processes" view
2. Switch to "Memory Analysis" and enter the PID
3. Review RWX memory regions / private executable memory / non-image executable regions

Key findings:
- Shellcode injection (RWX memory)
- Reflective DLL loading (private executable)
- Fileless attacks (non-image executable)

---

## Technical Implementation

| Module | Implementation |
|--------|----------------|
| Process Enumeration | CreateToolhelp32Snapshot + NtQueryInformationProcess (reads PEB command line) |
| File Hashing | SHA256 + MD5, with thread-safe caching |
| Digital Signatures | WinVerifyTrust + GetFileVersionInfo |
| Network Connections | GetExtendedTcpTable / GetExtendedUdpTable (TCP/UDP IPv4/IPv6) |
| Persistence | Registry API + Scheduled Tasks XML parsing + SCM API + WMI PowerShell queries |
| Event Logs | wevtutil (supports live logs and offline .evtx files) |
| DLL Modules | CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) + WinVerifyTrust |
| Memory Analysis | VirtualQueryEx |
| IOC Monitor | GetExtendedTcpTable polling (1-second interval) |
| YARA | Pure Go rule parser + pattern matching engine |
| AI Analysis | Claude API (English) / MiniMax API (Chinese) proxy + multi-turn conversation + automatic scan data formatting |
| GUI | Embedded HTTP server + HTML/CSS/JS single-page application |

---

## Project Structure

```
procir/
├── cmd/procir/main.go          # Entry point
├── internal/
│   ├── process/                 # Process enumeration
│   ├── file/                    # File hashing
│   ├── signature/               # Digital signatures
│   ├── context/                 # LOLBin / impersonation / parent-child chain
│   ├── network/                 # Network connections
│   ├── persistence/             # Persistence (legacy, for process correlation)
│   ├── trigger/                 # Trigger collection (7 types)
│   ├── forensic/                # Historical forensics (4 types)
│   ├── event/                   # Event logs (8 sources)
│   ├── module/                  # DLL sideloading detection
│   ├── memory/                  # Memory analysis
│   ├── yara/                    # YARA engine
│   ├── iocmonitor/              # IOC dynamic monitoring
│   ├── rules/                   # Process scoring engine
│   ├── fusion/                  # Fusion engine
│   ├── scoring/                 # Scan orchestrator
│   ├── export/                  # CLI export engine (JSON/CSV)
│   ├── timeline/                # Timeline engine
│   ├── behavior/                # Behavior chain identification
│   ├── indicator/               # IOC extraction
│   ├── proctree/                # Process tree + directory ecosystem
│   ├── types/                   # Data structures
│   └── gui/                     # Web UI
└── go.mod
```

**55+ Go source files, 12,000+ lines of code, 11MB compiled binary, only external dependency: `golang.org/x/sys`.**

---

## System Requirements

- Windows Server 2016+ / Windows 10+
- **Running as Administrator is recommended** (some features such as memory analysis and module enumeration require elevated privileges)
- No Go environment needed — run the pre-compiled exe directly

---

## Usage Recommendations

1. **Start with the "Execution Objects" view** — this is the core view that fuses all dimensions, sorted by score from high to low
2. **Focus on Critical and High** — a single dimension alone rarely reaches High; if it does, multiple dimensions have stacked
3. **Use the right-click menu** — copy SHA256 → verify on VirusTotal
4. **Double-click for details** — see the score breakdown and understand why an object was flagged
5. **Use YARA for secondary confirmation** — run custom rules against suspicious files
6. **Use Memory Analysis for deep inspection** — examine the memory layout of high-risk processes
7. **Use IOC Monitor for dynamic validation** — input threat intelligence IPs and check for real-time communication
8. **Use AI Analysis for intelligent assessment** — submit scan data to AI in one click for professional analysis conclusions and remediation recommendations

---

## Disclaimer

1. **This tool is intended solely for lawful security research, penetration testing, incident response, and educational purposes.** Users must ensure they have obtained legitimate authorization for the target system and comply with all applicable local laws and regulations.
2. **This tool does not provide any malware removal capabilities.** ProcIR is an analysis assistance tool; all detection results are reference indicators only, and final determinations require professional analysis by security engineers.
3. **False positives and false negatives.** Rule-based detection inevitably produces both false positives and false negatives. A high score does not necessarily indicate malware, and a low score does not guarantee safety. Please make comprehensive judgments based on the actual environment.
4. **Usage risks.** During operation, this tool reads system data including process information, file contents, registry entries, event logs, and memory layouts. Although all operations are read-only and do not modify system state, please assess potential impact when using in production environments.
5. **Liability waiver.** The author assumes no responsibility for any direct or indirect damages resulting from the use of this tool. By using this tool, you acknowledge and accept the above terms.

---

## License

This project is for educational and authorized security testing use only.

---

*ProcIR — Stay one step ahead in incident response.*
