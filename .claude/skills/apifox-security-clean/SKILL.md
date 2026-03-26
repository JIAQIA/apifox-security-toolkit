---
name: apifox-security-clean
description: 清理 ApiFox 供应链投毒攻击在本机残留的恶意缓存和网络记录，并屏蔽 C2 域名。应在 apifox-security-check 确认中招后执行。目前仅支持 macOS。
---

# ApiFox 供应链投毒攻击 -- 本地清理

在 [apifox-security-check]({baseDir}/../apifox-security-check/SKILL.md) 确认中招后，执行本流程清理恶意残留。

> **前置条件：** 已通过 `apifox-security-check` 确认存在感染标记（`rl_mc`/`rl_headers` 或 `apifox.it.com` 连接记录）。如果尚未排查，应先执行排查 skill。

> **平台支持：** 目前仅实现 macOS 清理流程。Windows / Linux 欢迎社区贡献。

## 为什么需要手动清理

ApiFox 自身**没有提供清理缓存的 UI 入口**。升级到 v2.8.19+ 只是修复了恶意 JS 的加载机制，但以下残留不会自动消失：

| 残留类型 | 风险 | 说明 |
|----------|------|------|
| Local Storage LevelDB | 高 | 恶意代码写入的感染标记（`rl_mc`/`rl_headers`），可被后续恶意脚本识别 |
| Network Persistent State | 中 | C2 域名 `apifox.it.com` 的 HSTS/连接记录，降级攻击可利用 |
| Cache / Code Cache | 中 | 可能缓存了被篡改的 77KB 恶意 JS 及其编译产物 |
| Session Storage | 低 | 攻击期间的会话数据 |

清理后重启 ApiFox（v2.8.19+）会自动重建干净的本地数据，不影响正常使用。

## 清理步骤（macOS）

### Step 1：退出 ApiFox

必须先完全退出所有 ApiFox 进程，否则文件被占用无法删除。

```bash
# 终止所有 ApiFox 进程
pkill -f "Apifox"

# 等待 2 秒后验证进程已全部退出
sleep 2
ps aux | grep -i apifox | grep -v grep | wc -l
# 预期输出: 0
```

**判断：** 输出为 `0` 才可继续。如不为 0，可尝试 `kill -9` 强制终止。

### Step 2：清理恶意残留文件

逐一删除以下目录/文件，每一步确认输出：

```bash
APP_DATA=~/Library/Application\ Support/apifox

# 1. Local Storage LevelDB（含感染标记 rl_mc/rl_headers）
rm -rf "$APP_DATA/Local Storage/leveldb/"

# 2. Network Persistent State（含 C2 域名 apifox.it.com 连接记录）
rm -f "$APP_DATA/Network Persistent State"

# 3. Cache（可能缓存被篡改的恶意 JS）
rm -rf "$APP_DATA/Cache/"

# 4. Code Cache（恶意 JS 的 V8 编译缓存）
rm -rf "$APP_DATA/Code Cache/"

# 5. Session Storage（攻击期间的会话数据）
rm -rf "$APP_DATA/Session Storage/"
```

> **注意：** 此操作不会删除 ApiFox 的项目数据（API 文档、环境配置等），这些存储在 `apifox-data/` 和 `data-storage-*.json` 中，不在清理范围内。

### Step 3：验证清理结果

三项验证全部通过才算清理完成：

```bash
APP_DATA=~/Library/Application\ Support/apifox

# 验证 1：感染标记已清除
grep -arlE "rl_mc|rl_headers" "$APP_DATA/Local Storage/" 2>/dev/null || echo "PASS: 无感染标记残留"

# 验证 2：C2 域名记录已清除
grep -rl "apifox.it.com" "$APP_DATA/" 2>/dev/null || echo "PASS: 无 C2 域名残留"

# 验证 3：缓存目录已删除
for dir in "Cache" "Code Cache" "Session Storage"; do
  ls "$APP_DATA/$dir" 2>/dev/null && echo "FAIL: $dir 仍存在" || echo "PASS: $dir 已删除"
done
```

**预期输出：** 5 个 PASS，0 个 FAIL。

### Step 4：屏蔽 C2 域名

即使恶意 JS 不再加载，仍建议在 DNS 层面屏蔽已知 C2 域名，防止其他途径的二次利用。

已知的完整恶意域名列表：

| 域名 | 用途 |
|------|------|
| `apifox.it.com` | 主 C2 服务器，接收窃取的数据 |
| `cdn.openroute.dev` | 恶意载荷分发（伪装为 CDN 服务） |
| `upgrade.feishu.it.com` | 伪装为飞书升级域名 |
| `ns.feishu.it.com` | 伪装为飞书 DNS |
| `system.toshinkyo.or.jp` | 被入侵的日本域名，用作跳板 |

```bash
# 检查 C2 域名是否仍可解析
for domain in apifox.it.com cdn.openroute.dev upgrade.feishu.it.com ns.feishu.it.com system.toshinkyo.or.jp; do
  nslookup "$domain" 2>&1 | grep -q "Address.*[0-9]" && echo "WARNING: $domain 仍可解析" || echo "OK: $domain 已不可解析"
done
```

如果有域名仍可解析，需要在 `/etc/hosts` 中添加屏蔽。由于修改 hosts 文件需要 sudo 权限，Claude Code 无法直接执行，**必须输出命令文本让用户手动操作**。

向用户输出以下提示（使用 `!` 前缀在当前会话中执行）：

```
请在提示符中输入以下命令（会要求输入系统密码）：

! sudo tee -a /etc/hosts <<'EOF'

# Apifox supply chain attack C2 domains (2026-03)
127.0.0.1 apifox.it.com
127.0.0.1 cdn.openroute.dev
127.0.0.1 upgrade.feishu.it.com
127.0.0.1 ns.feishu.it.com
127.0.0.1 system.toshinkyo.or.jp
EOF
```

等待用户确认操作完成后，执行复验：

```bash
# 复验：确认 hosts 中已包含所有 C2 域名
for domain in apifox.it.com cdn.openroute.dev upgrade.feishu.it.com ns.feishu.it.com system.toshinkyo.or.jp; do
  grep -q "$domain" /etc/hosts && echo "PASS: $domain 已屏蔽" || echo "FAIL: $domain 未屏蔽"
done
```

**预期输出：** 5 个 PASS，0 个 FAIL。如有 FAIL，提示用户重新执行对应域名的添加。

### Step 5：输出清理报告

清理完成后，向用户输出结构化报告：

```
## 清理结果

| 清理项 | 状态 |
|--------|------|
| Local Storage/leveldb | 已清除 |
| Network Persistent State | 已清除 |
| Cache | 已清除 |
| Code Cache | 已清除 |
| Session Storage | 已清除 |
| C2 域名屏蔽 | 已屏蔽 / 待用户确认 |

现在可以重启 ApiFox（v2.8.19+），将自动重建干净的本地数据。
```

最后，**必须提醒用户**：本地缓存清理只消除了恶意残留，攻击期间已泄露的凭证（SSH 密钥、Git 凭证等）仍需轮换，建议继续执行 `apifox-security-check` 中的处置建议。

## Windows / Linux 清理（待补充）

> Windows 数据目录：`%APPDATA%/apifox/`，Linux 数据目录：`~/.config/apifox/`。
> 清理目标与 macOS 一致，仅路径不同。欢迎社区贡献 PR。
