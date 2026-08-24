# 内置 Web 字典

本目录只保存压缩后的运行时字典，避免把 70 MiB 原始合并文件写入 Git 历史。

| 文件 | 解压格式 | 条目数 | SHA-256 |
|---|---|---:|---|
| `paths.tsv.gz` | `路径<TAB>directory\|route\|file` | 3,378,432 | `e0212c7a867f428fe9ad9a793e8cad7d3ee2c447dae87ddf4e62552945760b51` |
| `leaks.tsv.gz` | `路径<TAB>泄漏类型<TAB>可选响应签名` | 153,737 | `bd23cceb6cc01d63d5dec0ca39845ac775a4a97e6ac961cc20fc95f5cefcb79b` |

来源：

- DirectoryFuzz 全部 26 个 TXT 字典，快照 `10941567fc72be4ab93831221eca79ac38fcc154`。
- dirsearch v0.5.0 全部 34 个 categories TXT 字典，快照 `6d685189ed7f3871ab02ca2ce9c3d326fa457b27`。
- EasyScan 原有内置路径。

路径类型是根据文件名和常见目录名称生成的预测标签，用于展示与筛选；它不表示服务端真实文件系统结构。泄漏字典只包含敏感文件候选，普通 JavaScript、PHP、ASP、JSP 等文件仍只属于路径发现字典。

两个文件包含 dirsearch 派生条目，按 `GPL-2.0-only` 分发。
