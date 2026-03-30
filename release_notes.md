## ProcIR v1.5.0 - Windows 应急响应进程排查工具

面向安全工程师的一键式应急响应工具，快速定位木马、后门、持久化、白加黑、内存注入等威胁。

### v1.5.0 — 新增 CLI 模式 & 数据导出

本次更新新增纯命令行运行模式，支持无 GUI 环境下的自动化扫描与数据导出，同时支持 YARA 扫描结果独立导出。

#### CLI 模式（纯命令行）

- **无需 GUI**：`-cli` 参数启动纯命令行模式，扫描完成后直接导出数据文件
- **适用场景**：自动化脚本、远程 SSH、无桌面环境、批量扫描、SIEM 集成
- **实时进度**：扫描过程中显示进程分析进度和耗时
- **扫描摘要**：完成后输出风险分布统计、YARA 匹配数、行为链/IOC/时间线汇总

#### 数据导出

- **JSON 全量导出**：ExecutionObjects、Processes、Triggers、Forensics、Events、Modules、Timeline、BehaviorChains、Indicators，附带 Summary 统计
- **CSV 全量导出**：ExecutionObjects 27 列关键字段，含 YARA 匹配状态和评分
- **YARA 专项导出**：`-yara-export` 参数仅导出 YARA 命中对象，含规则名、标签、匹配分数
- **自动文件名**：不指定 `-o` 时自动生成带时间戳的文件名

#### CLI 参数

| 参数 | 说明 |
|------|------|
| `-cli` | 启用 CLI 模式（不启动 GUI） |
| `-o <path>` | 指定导出文件路径 |
| `-format json\|csv` | 导出格式，默认 json |
| `-yara <path>` | YARA 规则文件或目录 |
| `-yara-export` | 仅导出 YARA 匹配结果 |

#### 使用示例

```bash
# 全量扫描导出 JSON
procir.exe -cli -o result.json

# 全量扫描导出 CSV
procir.exe -cli -o result.csv -format csv

# 加载 YARA 规则，仅导出匹配结果
procir.exe -cli -yara ./rules -yara-export -o yara_hits.json

# 自动生成文件名
procir.exe -cli
```

#### 其他改进

- 新增 `internal/export` 包，统一处理 CLI 和未来的 API 数据导出
- 新增 13 条中英文 CLI 提示消息（i18n 双语）
- 项目代码量增至 55+ Go 源文件，12,000+ 行

---

### 使用

```
procir.exe                    # GUI 模式（默认）
procir.exe -yara rules.yar   # GUI 模式 + YARA 规则
procir.exe -cli -o scan.json # CLI 模式，导出 JSON
```
