## ProcIR v1.5.3 - Windows 应急响应进程排查工具

面向安全工程师的一键式应急响应工具，快速定位木马、后门、持久化、白加黑、内存注入等威胁。

### v1.5.3 — 界面交互修复

#### 修复

- **修复表格行选中偏移**：点击第 N 行实际高亮第 N-1 行。原因是 `sel()` 函数的 CSS 选择器 `querySelectorAll('.view-panel.active tr')` 包含了 `<thead>` 表头行，导致索引偏移 1。修改为 `.view-panel.active tbody tr` 仅匹配数据行

---

### 使用

```
procir.exe                    # GUI 模式（默认）
procir.exe -cli -o scan.json # CLI 模式，导出 JSON
```
