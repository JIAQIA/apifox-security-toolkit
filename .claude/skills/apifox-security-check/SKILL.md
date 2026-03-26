---
name: apifox-security-check
description: 检查本机是否受 ApiFox 2026年3月供应链投毒攻击影响。当用户担心 ApiFox 安全问题、需要排查敏感凭证泄露风险时使用。目前仅支持 macOS 检查流程。
---

# ApiFox 供应链投毒攻击排查

检查本机 ApiFox 桌面端是否在 2026-03-04 至 2026-03-22 攻击窗口期内被投毒，评估敏感资产泄露风险并给出处置建议。

> **平台支持：** 目前仅实现 macOS 检查流程。Windows / Linux 检查流程欢迎社区贡献 PR 补充。

## 攻击背景

| 项目 | 详情 |
|------|------|
| 攻击方式 | CDN 上的 `apifox-app-event-tracking.min.js` 被篡改（34KB->77KB），启动时自动加载恶意载荷 |
| 攻击窗口 | 2026-03-04 至 2026-03-22（18天） |
| C2 域名 | `apifox.it.com`（已下线）、`cdn.openroute.dev`、`upgrade.feishu.it.com`、`ns.feishu.it.com`、`system.toshinkyo.or.jp` |
| 窃取目标 | SSH 密钥、Git 凭证、Shell 历史、K8s 配置、npm Token、进程列表 |
| 修复版本 | v2.8.19（2026-03-23），改为内置 JS 文件 |
| 参考来源 | [完整技术分析](https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/)、[蓝点网报道](https://www.landiannews.com/archives/112328.html) |

## 排查步骤（macOS）

按以下顺序逐步执行，每一步的输出决定下一步的判断。

### Step 1：确认 ApiFox 是否安装

```bash
# 检查安装位置
ls -la /Applications/Apifox.app 2>/dev/null
mdfind "kMDItemFSName == 'Apifox*'" 2>/dev/null

# 读取当前版本
defaults read /Applications/Apifox.app/Contents/Info.plist CFBundleShortVersionString 2>/dev/null
```

**判断：**
- 未安装 -> 不受影响，排查结束
- 已安装 -> 记录版本号，继续 Step 2

### Step 2：检查是否连接过恶意 C2 服务器（核心判据）

```bash
# 检查 Network Persistent State 中是否记录了到 C2 的连接
cat ~/Library/Application\ Support/apifox/Network\ Persistent\ State 2>/dev/null \
  | python3 -m json.tool 2>/dev/null \
  | grep -A2 -B2 "apifox.it"
```

**判断：**
- 找到 `"server": "https://apifox.it.com"` -> **确认中招**，继续 Step 3
- 未找到 -> 继续 Step 3 做二次确认

### Step 3：检查 LevelDB 感染标记

```bash
# 在 localStorage 的 LevelDB 中搜索感染标记
strings ~/Library/Application\ Support/apifox/Local\ Storage/leveldb/*.ldb \
        ~/Library/Application\ Support/apifox/Local\ Storage/leveldb/*.log 2>/dev/null \
  | grep -iE '_rl_headers|_rl_mc|af_uuid|af_os|af_email|af_name'
```

**判断：**
- 存在 `_rl_headers` 或 `af_uuid`/`af_os` 等字段 -> **确认中招**
- Step 2 和 Step 3 均无发现 -> 未受影响，排查结束

### Step 4：评估泄露资产范围

确认中招后，盘点本机可能已泄露的敏感资产：

```bash
# SSH 密钥
ls -la ~/.ssh/ 2>/dev/null

# Git 凭证
ls -la ~/.git-credentials 2>/dev/null
git config --global credential.helper 2>/dev/null

# K8s 配置
ls -la ~/.kube/config 2>/dev/null

# npm Token
ls -la ~/.npmrc 2>/dev/null

# Shell 历史（可能包含硬编码密码）
ls -la ~/.zsh_history ~/.bash_history 2>/dev/null
```

**输出：** 生成一份资产清单表格，标注风险等级：

| 资产 | 路径 | 是否存在 | 风险等级 |
|------|------|----------|----------|
| SSH 密钥 | `~/.ssh/*` | ? | 严重 |
| K8s 配置 | `~/.kube/config` | ? | 严重 |
| Git 凭证 | `~/.git-credentials` | ? | 高 |
| Shell 历史 | `~/.zsh_history` / `~/.bash_history` | ? | 高 |
| npm Token | `~/.npmrc` | ? | 中 |

### Step 5：检查 ApiFox 进程和网络连接

```bash
# 查看运行中的 ApiFox 进程
ps aux | grep -i apifox | grep -v grep

# 检查网络连接
lsof -i -n -P | grep -i apifox 2>/dev/null
```

**判断：** 确认当前连接目标是否为已知的官方服务器（阿里云 IP），排除持续的恶意连接。

### Step 6：检查持久化机制

```bash
# 检查是否有异常 LaunchAgent/LaunchDaemon
ls -la ~/Library/LaunchAgents/ | grep -i apifox
ls -la /Library/LaunchAgents/ | grep -i apifox 2>/dev/null
ls -la /Library/LaunchDaemons/ | grep -i apifox 2>/dev/null
```

**判断：** 正常情况下不应有 ApiFox 相关的 LaunchAgent/Daemon。如有发现，需进一步分析 plist 内容。

## 处置建议

确认中招后，向用户输出以下处置清单（按优先级排序）：

1. **立即轮换所有 SSH 密钥** -- 重新生成密钥对，在 GitHub/GitLab/服务器上替换公钥
2. **吊销并重新签发 K8s 凭证** -- 特别注意集群 admin 权限的 Token
3. **轮换 npm Token** -- 在 npmjs.com 吊销旧 Token
4. **审查 Shell 历史** -- 搜索硬编码的密码、API Key、Token，逐一轮换
5. **审查服务器登录日志** -- 重点排查 3月4日-22日 期间的异常 SSH 登录
6. **确认 ApiFox 版本 >= v2.8.19** -- 低于此版本需立即升级

## Windows / Linux 排查（待补充）

> 本 Skill 目前仅覆盖 macOS 平台。攻击同样影响 Windows 和 Linux 平台。
>
> **欢迎贡献：** 如果你有 Windows 或 Linux 环境，欢迎参考 macOS 流程，补充对应平台的：
> - ApiFox 数据目录路径（Windows 通常在 `%APPDATA%/apifox/`）
> - LevelDB 和 Network Persistent State 的检查命令
> - 敏感资产的平台差异路径（如 Windows 的 `%USERPROFILE%\.ssh\`）
>
> 请提交 PR 到本项目补充。
