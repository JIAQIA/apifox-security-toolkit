# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ApiFox 2026年3月供应链投毒事件的检测、评估与修复工具集。目前以 Claude Code Skills 形式提供，无需构建或安装，通过 `/skill-name` 直接调用。

## Skills Architecture

本项目的核心功能以 Skills 实现，位于 `.claude/skills/`，形成三阶段处置链：

```
apifox-security-check  →  apifox-security-clean  →  apifox-credential-rotate
    排查是否中招              清理本地恶意残留            轮换泄露凭证
```

- **apifox-security-fix** — 一站式入口，整合上述三阶段，根据用户当前进度智能跳转
- **create-skill** — 创建新 Skill 的脚手架工具

## Key Design Decisions

- **仅支持 macOS**：所有路径和命令基于 macOS。Windows/Linux 待社区贡献。
- **macOS 数据目录**：`~/Library/Application Support/apifox/`
- **zsh 兼容性**：SSH 密钥扫描脚本必须通过 `bash -c '...'` 执行，因为 zsh glob 无匹配时会报错中断。
- **sudo 操作**：修改 `/etc/hosts` 等需要 sudo 的操作，必须输出命令文本让用户手动执行（`!` 前缀），然后复验。
- **凭证轮换安全流程**：备份旧密钥（`_old` 后缀）→ 生成新密钥 → 平台替换 → 验证连通性 → 验证通过后才删除旧密钥。
- **K8s Kubeconfig 比对**：用 MD5 比较完整证书内容，不要只比前几十个字符（base64 头部结构相同会导致误判）。
- **逐项确认**：每个凭证轮换前必须用 AskUserQuestion 确认，用户可能已手动处理或判断风险可控。

## Attack IOCs

C2 域名（需在 /etc/hosts 屏蔽）：
- `apifox.it.com`、`cdn.openroute.dev`、`upgrade.feishu.it.com`、`ns.feishu.it.com`、`system.toshinkyo.or.jp`

LevelDB 感染标记：`rl_mc`、`rl_headers`

攻击窗口：2026-03-04 至 2026-03-22，修复版本 v2.8.19+
