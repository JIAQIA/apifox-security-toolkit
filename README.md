# ApiFox Security Toolkit

ApiFox 2026年3月供应链投毒事件的检测、评估与修复工具集。

## 前置要求

本工具集以 [Claude Code](https://claude.ai/code) Skills 形式提供，需要在本地安装 Claude Code 后使用：

```bash
# macOS / Linux
npm install -g @anthropic-ai/claude-code

# 在本项目目录中启动
cd apifox-security-toolkit
claude
```

## 使用方式

在 Claude Code 中通过斜杠命令调用对应功能：

| 命令 | 功能 |
|------|------|
| `/apifox-security-fix` | **一站式修复**（推荐），根据当前进度智能跳转排查、清理、轮换全流程 |
| `/apifox-security-check` | 检测本机是否受影响 |
| `/apifox-security-clean` | 清理本地恶意缓存和 C2 域名残留 |
| `/apifox-credential-rotate` | 扫描并轮换泄露的 SSH 密钥、Git 凭证、K8s 配置等 |

如需浏览器辅助操作（自动在 GitHub 等平台删除/添加密钥），还需安装 Playwright MCP：

```bash
claude mcp add playwright -- npx @anthropic-ai/mcp-playwright@latest
```

> 目前仅支持 macOS。Windows / Linux 欢迎贡献 PR。

## 参考资料

- [Apifox 供应链攻击事件分析](https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/)
- [关于 Apifox 外部 JS 文件受篡改的风险提示与升级公告（官方）](https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig)
