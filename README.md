# ProcIR - Windows 应急响应进程排查工具

[![GitHub Release](https://img.shields.io/github/v/release/dogadmin/ProcIR)](https://github.com/dogadmin/ProcIR/releases/latest)
**中文** | [English](README_EN.md)

> 面向安全工程师的一键式应急响应工具，快速定位木马、后门、持久化、白加黑、内存注入等威胁。

---

## 工具定位

ProcIR 是一个**非常驻、非 Agent、纯本地**的 Windows 应急响应排查工具。

设计场景：你接到应急响应任务，上机后需要在最短时间内搞清楚：

- 哪些进程可疑？
- 有没有持久化后门？
- 有没有白加黑 / DLL 劫持？
- 有没有历史执行痕迹？
- 攻击链是怎样的？

传统做法是手动跑一堆命令（tasklist、netstat、autoruns、schtasks...），逐个比对，费时费力。ProcIR 把这些全自动化了，一次扫描，全维度分析，按风险排序，直接告诉你该看哪个。

**核心理念：不是杀软，不做查杀，只做发现和研判辅助。**

---

## 特性

- **单文件运行**，无需安装，无外部依赖，11MB
- **纯 Go 实现**，无 CGO，拷贝即用
- **非常驻**，扫描完就退，不影响业务
- **不联网**，所有分析纯本地完成（AI 分析功能除外，需联网调用 API）
- **双模式运行**：内嵌 Web UI（GUI）+ 纯命令行模式（CLI），支持 JSON/CSV 导出
- **13 个分析视图**，覆盖从进程到内存的完整攻击面
- **AI 智能分析**，中文 MiniMax / 英文 Claude，一键将扫描结果交给 AI 研判
- **中英文全量双语**，UI + 后端 400+ 条检测规则/风险原因全部支持中英文切换

---

## 快速开始

### GUI 模式（默认）

```
# 直接运行，自动打开浏览器
procir.exe

# 带 YARA 规则
procir.exe -yara rules.yar
procir.exe -yara C:\yara-rules\
```

运行后自动打开浏览器，点「开始扫描」，等待数秒即可看到结果。

### CLI 模式（纯命令行）

无需 GUI，扫描完成后直接导出数据文件，适合自动化脚本、远程 SSH、无桌面环境等场景。

```bash
# 扫描并导出 JSON（默认格式）
procir.exe -cli -o result.json

# 扫描并导出 CSV
procir.exe -cli -o result.csv -format csv

# 加载 YARA 规则扫描，导出全量结果
procir.exe -cli -yara ./rules -o scan.json

# 仅导出 YARA 匹配结果
procir.exe -cli -yara ./rules -yara-export -o yara_hits.json

# 不指定 -o，自动生成带时间戳的文件名
procir.exe -cli
```

**CLI 参数：**

| 参数 | 说明 |
|------|------|
| `-cli` | 启用 CLI 模式（不启动 GUI） |
| `-o <path>` | 指定导出文件路径 |
| `-format json\|csv` | 导出格式，默认 json |
| `-yara <path>` | YARA 规则文件或目录 |
| `-yara-export` | 仅导出 YARA 匹配结果 |

**导出内容：**

- **JSON 全量导出**：ExecObjects、Processes、Triggers、Forensics、Events、Modules、Timeline、BehaviorChains、Indicators + Summary 统计
- **CSV 全量导出**：ExecObjects 27 列关键字段（含 YARA 列）
- **YARA 专项导出**：仅 YARA 命中对象，含规则名、标签、匹配分数

---

## 分析能力总览

ProcIR 从 **9 个维度** 分析系统状态，覆盖攻击生命周期的每个阶段：

```
┌──────────────────────────────────────────────────────────┐
│  Execution Plane（运行态）                                │
│  当前所有活跃进程 → 命令行/父子链/签名/网络/持久化          │
├──────────────────────────────────────────────────────────┤
│  Trigger Plane（触发态）                                  │
│  注册表Run → Startup → 计划任务 → 服务 → WMI → IFEO       │
├──────────────────────────────────────────────────────────┤
│  Forensic Plane（历史态）                                 │
│  Prefetch → 最近文件修改 → 事件日志 → DLL模块              │
├──────────────────────────────────────────────────────────┤
│  Event Plane（事件态）                                    │
│  Security → System → PowerShell → TaskScheduler → Sysmon │
├──────────────────────────────────────────────────────────┤
│  Module Plane（模块态）                                   │
│  DLL Sideload → 白加黑 → 系统DLL伪装 → 同目录加载         │
├──────────────────────────────────────────────────────────┤
│  YARA Plane（内容态）                                     │
│  纯Go YARA引擎 → 自定义规则 → 文件内容匹配                │
├──────────────────────────────────────────────────────────┤
│  Memory Plane（内存态）                                   │
│  指定PID → VirtualQueryEx → RWX/私有可执行/无文件注入      │
├──────────────────────────────────────────────────────────┤
│  IOC Monitor（动态监控）                                  │
│  IP IOC → TCP连接表轮询 → 实时命中 → 进程归因              │
├──────────────────────────────────────────────────────────┤
│  AI Analysis（智能分析）                                   │
│  MiniMax 大模型 → 扫描数据一键投喂 → 多轮对话研判          │
└──────────────────────────────────────────────────────────┘
                         ↓
              Fusion Engine（融合引擎）
              → ExecutionObject 统一模型
              → 多维叠加评分
              → 行为链识别
              → 时间线还原
              → IOC 自动提取
```

---

## 13 个分析视图

| 视图 | 功能 |
|------|------|
| **活跃进程** | 所有运行进程，按风险评分排序，命令行/签名/网络/持久化一目了然 |
| **触发器** | 所有持久化入口（Run/Task/Service/WMI/IFEO/Winlogon），独立评分 |
| **执行对象** | 核心视图：进程+触发器+取证+事件+模块+YARA 多维融合，统一评分 |
| **历史取证** | Prefetch 执行记录、最近文件修改、事件日志、可疑模块 |
| **事件日志** | Security/System/PowerShell/TaskScheduler/WMI/Sysmon 高价值事件 |
| **模块分析** | DLL 劫持检测：白加黑/同目录侧加载/系统DLL名伪装 |
| **时间线** | 全部事件按时间排序，还原攻击路径 |
| **行为链** | 自动识别攻击模式：宏攻击链/浏览器利用链/WMI后门链/下载执行链 |
| **IOC** | 自动从命令行/触发器/事件中提取 URL/IP/域名/Base64 |
| **YARA** | 独立页面：上传规则 → 全量扫描 → 命中结果 → 规则详情 |
| **内存分析** | 指定 PID 深度分析：RWX 内存/私有可执行/无映像执行 |
| **IOC 监控** | 输入 IP/域名列表 → 实时监控 TCP 连接 → 命中告警+进程归因 |
| **AI 分析** | 集成 MiniMax 大模型，一键发送扫描数据，多轮对话智能研判 |

---

## 评分模型

ProcIR 的评分不是简单规则匹配，而是一个**多层融合模型**：

### 第一层：基础规则（每个维度独立打分）

```
进程评分 = 签名(±8) + 路径(±10~20) + 伪装(+30) + 父子链(+10~25)
         + 命令行(+20~30) + 网络(+10~20) + 持久化(+20~25)
         → 强规则Override → 组合加权Synergy → 白特征Anti-FP → 上下文权重(×1.2~1.5)

触发器评分 = 基础(+15~30) + 路径(+20) + 命令行(+20~30) + Task特征(+10) + Service特征(+10~25)

事件评分 = EventID权重(+5~30) + 命令行检测(+15~20) + LOLBin识别(+15)

模块评分 = 未签名(+20) + 用户目录(+25) + 系统DLL伪装(+30) + 白加黑(+40) + 同目录(+35) + 系统进程异常(+50)

YARA评分 = 每规则(+20) + 高危标签(+30) + 多规则(+15) + 外联联动(+20) + 持久化联动(+15)
```

### 第二层：融合评分

```
FinalScore = ExecutionScore + TriggerScore + ForensicScore + EventScore
           + DLLHijackScore + YaraScore
           + BehaviorChainScore + DirClusterScore
           + SynergyBonus - WhiteReduction
```

### 第三层：融合规则

| 规则 | 分值 |
|------|------|
| 未运行但触发器高危 | 至少 Medium(40) |
| 触发器含 PowerShell 编码执行 | 至少 Critical(80) |
| 用户目录 + 自启动 | +20 |
| 运行中 + 外联 + 持久化 | +20 |
| 3+ 种触发器指向同一对象 | 至少 Critical(80) |
| 历史执行 + 持久化 | +20 |
| 事件证据 + 持久化 | +20 |
| 事件证据 + YARA 命中 | +20 |
| DLL 劫持 + 外联 | +20 |

### 风险等级

| 分数 | 等级 | 含义 |
|------|------|------|
| 0-19 | 低危 | 基本正常，可忽略 |
| 20-39 | 可疑 | 需要留意 |
| 40-59 | 中危 | 建议重点排查 |
| 60-79 | 高危 | 优先处置 |
| 80+ | 严重 | 立即响应 |

---

## 检测覆盖

| 威胁类型 | 检测手段 |
|----------|----------|
| LOLBin 滥用 | 40+ LOLBin 列表 + 命令行深度匹配 |
| 白加黑 / DLL Sideload | 签名进程+未签名DLL / 同目录加载 / 系统DLL名伪装 |
| Office 宏攻击 | 父子进程链（Office→脚本引擎） |
| PowerShell 攻击 | -enc/隐藏窗口/下载/IEX + 4104脚本日志 |
| 持久化后门 | Run/RunOnce/Startup/计划任务/服务/WMI/IFEO/Winlogon |
| WMI 持久化 | EventFilter + Consumer + Binding 完整链路 |
| 系统文件伪装 | 14 个系统进程名 + 合法路径比对 |
| 间歇执行/定时后门 | Prefetch + 计划任务 + 事件日志交叉关联 |
| 已清理样本 | Prefetch 残留 + 事件日志(4688/7045/4698) |
| 内存注入 / Fileless | VirtualQueryEx 枚举 RWX/私有可执行内存 |
| C2 外联 | TCP 连接表 + IOC 实时监控 |
| 横向移动痕迹 | 4624(网络登录)/4648(显式凭证)/4672(特权登录) |
| 提权行为 | 7045(服务安装) + LOLBin 提权命令 |

---

## 行为链自动识别

ProcIR 不只做单点检测，还能自动识别完整攻击链：

| 攻击链 | 检测模式 | 评分 |
|--------|----------|------|
| 宏攻击链 | Office → 脚本引擎 (+ -enc/download) | +25~40 |
| 浏览器利用链 | Browser → 系统工具 (排除 Native Messaging) | +20 |
| 持久化执行链 | 文件落地 + RunKey/Task + Prefetch 执行记录 | +15~20 |
| WMI 后门链 | WMI Consumer → 脚本引擎 → URL/编码 | +30 |
| DLL 侧加载链 | 进程加载用户目录未签名 DLL | +25 |
| 下载执行链 | cmd /c + curl/certutil + 执行 / PS download+IEX | +25~30 |

---

## YARA 集成

ProcIR 内置了一个**纯 Go 实现的 YARA 兼容引擎**（无需 CGO/GCC），支持：

- 文本字符串匹配（nocase / wide / ascii / fullword）
- 十六进制模式（含 `??` 通配符）
- 正则表达式
- 条件语法（any of them / all of them / N of / 布尔组合 / filesize）
- meta / tags

**使用方式：**

1. 切到「YARA」标签页
2. 点「选择规则文件」上传 `.yar` 文件，或输入本地路径加载
3. 点「开始扫描全部对象」
4. 查看命中结果

只扫描可疑对象（高评分/用户目录/未签名/有触发器），自动跳过已签名系统文件。

---

## IOC 监控

实时监控本机是否与恶意 IP 通信：

1. 切到「IOC 监控」标签页
2. 输入 IOC 列表（一行一个 IP 或域名）
3. 设置监控时长，点「开始监控」
4. 命中时实时显示进程名/路径/用户/端口

```
# IOC 格式
1.2.3.4
evil.com
1.2.3.4,high,intel_feed,C2 server
```

域名 IOC 在加载时自动解析为 IP。监控期间仅读取内核 TCP 连接表，**零网络影响**。

---

## AI 智能分析

集成 MiniMax 大模型，实现扫描结果的 AI 辅助研判：

1. 切到「AI 分析」标签页
2. 输入 MiniMax API Key（可勾选「记住 Key」保存到本地）
3. 选择模型（M2.5 / M2.5 高速 / M2.7 / M2.7 高速）
4. 点「发送扫描数据」将完整扫描结果一键投喂给 AI，或点「发送摘要」发送精简版
5. 也可以直接在输入框输入问题，进行多轮对话

**功能特点：**

- **一键投喂**：自动将高风险进程、可疑触发器、行为链、IOC、高危执行对象、可疑模块、历史取证、高危事件等全部扫描数据格式化后发送给 AI
- **多轮对话**：支持上下文连续对话，可追问细节
- **专业 Prompt**：内置 Windows 应急响应专家角色设定，AI 直接给结论和处置建议
- **Token 统计**：实时显示每轮和累计 Token 消耗
- **API Key 本地保存**：可选将 Key 存储在浏览器 localStorage

> 需要 MiniMax API Key，申请地址：platform.minimax.io

---

## 内存分析

对可疑进程进行内存级深度检测：

1. 在「活跃进程」视图发现可疑进程
2. 切到「内存分析」，输入 PID
3. 查看 RWX 内存区域 / 私有可执行内存 / 非映像可执行区域

主要发现：
- Shellcode 注入（RWX 内存）
- Reflective DLL 加载（私有可执行）
- 无文件攻击（非映像可执行）

---

## 技术实现

| 模块 | 实现方式 |
|------|----------|
| 进程枚举 | CreateToolhelp32Snapshot + NtQueryInformationProcess（读取 PEB 命令行） |
| 文件哈希 | SHA256 + MD5，带线程安全缓存 |
| 数字签名 | WinVerifyTrust + GetFileVersionInfo |
| 网络连接 | GetExtendedTcpTable / GetExtendedUdpTable（TCP/UDP IPv4/IPv6） |
| 持久化 | 注册表 API + Scheduled Tasks XML 解析 + SCM API + WMI PowerShell 查询 |
| 事件日志 | wevtutil（支持在线日志和离线 .evtx 文件） |
| DLL 模块 | CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) + WinVerifyTrust |
| 内存分析 | VirtualQueryEx |
| IOC 监控 | GetExtendedTcpTable 轮询（1秒间隔） |
| YARA | 纯 Go 实现的规则解析器 + 模式匹配引擎 |
| AI 分析 | MiniMax API 代理 + 多轮对话 + 扫描数据自动格式化 |
| GUI | 内嵌 HTTP 服务器 + HTML/CSS/JS 单页应用 |

---

## 项目结构

```
procir/
├── cmd/procir/main.go          # 入口
├── internal/
│   ├── process/                 # 进程枚举
│   ├── file/                    # 文件哈希
│   ├── signature/               # 数字签名
│   ├── context/                 # LOLBin/伪装/父子链
│   ├── network/                 # 网络连接
│   ├── persistence/             # 持久化（旧版，供进程关联）
│   ├── trigger/                 # 触发器采集（7种）
│   ├── forensic/                # 历史取证（4种）
│   ├── event/                   # 事件日志（8个来源）
│   ├── module/                  # DLL 白加黑检测
│   ├── memory/                  # 内存分析
│   ├── yara/                    # YARA 引擎
│   ├── iocmonitor/              # IOC 动态监控
│   ├── rules/                   # 进程评分引擎
│   ├── fusion/                  # 融合引擎
│   ├── scoring/                 # 扫描编排器
│   ├── export/                  # CLI 导出引擎（JSON/CSV）
│   ├── timeline/                # 时间线引擎
│   ├── behavior/                # 行为链识别
│   ├── indicator/               # IOC 提取
│   ├── proctree/                # 进程树 + 目录生态
│   ├── types/                   # 数据结构
│   └── gui/                     # Web UI
└── go.mod
```

**55+ 个 Go 源文件，12,000+ 行代码，编译产物 11MB，外部依赖仅 `golang.org/x/sys`。**

---

## 运行环境

- Windows Server 2016+ / Windows 10+
- **建议以管理员权限运行**（部分功能如内存分析、模块枚举需要提升权限）
- 无需安装 Go 环境，直接运行编译好的 exe

---

## 使用建议

1. **先看「执行对象」视图** — 这是融合了所有维度的核心视图，按评分从高到低排列
2. **重点关注 Critical 和 High** — 单一维度不会轻易到 High，能到说明多个维度叠加
3. **善用右键菜单** — 复制 SHA256 → 去 VirusTotal 验证
4. **双击查看详情** — 看评分构成，理解为什么这个对象被标记
5. **用 YARA 做二次确认** — 对可疑文件跑自定义规则
6. **用内存分析做深度检测** — 对高风险进程查看内存布局
7. **用 IOC 监控做动态验证** — 输入威胁情报 IP，看是否有实时通信
8. **用 AI 分析做智能研判** — 一键将扫描数据发送给 AI，获取专业分析结论和处置建议

---

## 免责声明

1. **本工具仅供合法的安全研究、渗透测试、应急响应和教育学习使用。** 使用者必须确保已获得目标系统的合法授权，遵守当地法律法规。
2. **本工具不提供任何形式的恶意软件查杀能力。** ProcIR 是一个辅助研判工具，所有检测结果仅为线索参考，最终判定需要安全工程师的专业分析。
3. **误报与漏报。** 基于规则的检测必然存在误报和漏报。高评分不代表一定是恶意软件，低评分也不代表一定安全。请结合实际环境综合研判。
4. **使用风险。** 本工具在运行过程中会读取进程信息、文件内容、注册表、事件日志、内存布局等系统数据。虽然所有操作均为只读且不修改系统状态，但在生产环境中使用时请评估潜在影响。
5. **免责。** 作者不对因使用本工具造成的任何直接或间接损失承担责任。使用本工具即表示您理解并接受以上条款。

---

## License

本项目仅供学习和授权安全测试使用。

---

*ProcIR — 让应急响应快一步。*
