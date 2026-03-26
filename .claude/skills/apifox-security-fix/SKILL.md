---
name: apifox-security-fix
description: ApiFox 2026年3月供应链投毒攻击一站式修复。整合排查、清理、凭证轮换全流程，根据用户当前进度智能跳转。当用户需要处理 ApiFox 安全事件时使用。目前仅支持 macOS。
---

# ApiFox 供应链投毒攻击 -- 一站式修复

本 Skill 整合排查、清理、凭证轮换三个阶段，根据用户当前进度智能跳转，避免重复操作。

> **平台支持：** 目前仅实现 macOS 流程。Windows / Linux 欢迎社区贡献 PR。

## 攻击背景

| 项目 | 详情 |
|------|------|
| 攻击方式 | CDN 上的 `apifox-app-event-tracking.min.js` 被篡改（34KB->77KB），启动时自动加载恶意载荷 |
| 攻击窗口 | 2026-03-04 至 2026-03-22（18天） |
| C2 域名 | `apifox.it.com`、`cdn.openroute.dev`、`upgrade.feishu.it.com`、`ns.feishu.it.com`、`system.toshinkyo.or.jp` |
| 窃取目标 | SSH 密钥、Git 凭证、Shell 历史、K8s 配置、npm Token、进程列表 |
| 修复版本 | v2.8.19（2026-03-23），改为内置 JS 文件 |
| 参考来源 | [完整技术分析](https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/)、[蓝点网报道](https://www.landiannews.com/archives/112328.html)、[离别歌复盘](https://www.leavesongs.com/PENETRATION/apifox-supply-chain-attack-analysis.html) |

---

## Phase 0：确认当前进度

**在执行任何操作之前，必须先用 `AskUserQuestion` 确认用户当前所处阶段。**

向用户提问：

```
在开始修复之前，请确认你当前的进度：

1. **尚未排查** -- 还不确定是否受影响，需要从头检测
2. **已确认中招，尚未清理** -- 已经确认受影响，但还没有清理本地恶意残留
3. **已确认中招，已完成清理** -- 本地残留已清理，需要轮换泄露的凭证
4. **已确认中招，已清理，部分凭证已轮换** -- 需要继续完成剩余凭证轮换

请回复 1、2、3 或 4。
```

**根据回复跳转：**

| 回复 | 跳转到 |
|------|--------|
| 1 | Phase 1（排查） |
| 2 | Phase 2（清理），跳过排查 |
| 3 | Phase 3（凭证轮换），跳过排查和清理 |
| 4 | Phase 3（凭证轮换），执行前先扫描已轮换的凭证状态 |

---

## Phase 1：排查是否受影响

> 如果用户已确认中招，跳过此阶段。

详细排查流程参见 [apifox-security-check]({baseDir}/../apifox-security-check/SKILL.md)，以下为执行摘要。

### 1.1 确认安装与版本

```bash
ls -la /Applications/Apifox.app 2>/dev/null && \
  defaults read /Applications/Apifox.app/Contents/Info.plist CFBundleShortVersionString 2>/dev/null || \
  echo "未安装 Apifox"
```

未安装 -> 不受影响，结束。

### 1.2 检查 C2 连接记录（核心判据）

```bash
cat ~/Library/Application\ Support/apifox/Network\ Persistent\ State 2>/dev/null \
  | python3 -m json.tool 2>/dev/null \
  | grep -A2 -B2 "apifox.it"
```

### 1.3 检查 LevelDB 感染标记

```bash
grep -arlE "rl_mc|rl_headers" ~/Library/Application\ Support/apifox/Local\ Storage/leveldb/ 2>/dev/null
```

### 1.4 检查持久化机制

```bash
ls -la ~/Library/LaunchAgents/ 2>/dev/null | grep -i apifox
ls -la /Library/LaunchAgents/ 2>/dev/null | grep -i apifox
ls -la /Library/LaunchDaemons/ 2>/dev/null | grep -i apifox
```

### 1.5 判定

- 1.2 或 1.3 任一发现 -> **确认中招**，自动进入 Phase 2
- 均未发现 -> **未受影响**，输出结论并结束

> **注意：** 如果用户已经执行过清理，1.2 和 1.3 的证据可能已被删除，此时检测结果为阴性不代表未中招。这正是 Phase 0 需要先询问用户的原因。

---

## Phase 2：清理本地恶意残留

> 如果用户已完成清理，跳过此阶段。

详细清理流程参见 [apifox-security-clean]({baseDir}/../apifox-security-clean/SKILL.md)，以下为执行摘要。

### 2.1 退出 ApiFox

```bash
pkill -f "Apifox" 2>/dev/null; sleep 2
ps aux | grep -i apifox | grep -v grep | wc -l
# 预期输出: 0
```

### 2.2 清理恶意残留

```bash
APP_DATA=~/Library/Application\ Support/apifox

rm -rf "$APP_DATA/Local Storage/leveldb/"
rm -f "$APP_DATA/Network Persistent State"
rm -rf "$APP_DATA/Cache/"
rm -rf "$APP_DATA/Code Cache/"
rm -rf "$APP_DATA/Session Storage/"
```

> 不会删除 ApiFox 项目数据（`apifox-data/`、`data-storage-*.json`）。

### 2.3 验证清理

```bash
APP_DATA=~/Library/Application\ Support/apifox

grep -arlE "rl_mc|rl_headers" "$APP_DATA/Local Storage/" 2>/dev/null || echo "PASS: 无感染标记残留"
grep -rl "apifox.it.com" "$APP_DATA/" 2>/dev/null || echo "PASS: 无 C2 域名残留"
for dir in "Cache" "Code Cache" "Session Storage"; do
  ls "$APP_DATA/$dir" 2>/dev/null && echo "FAIL: $dir 仍存在" || echo "PASS: $dir 已删除"
done
```

预期：5 个 PASS，0 个 FAIL。

### 2.4 屏蔽 C2 域名

先检查本机 hosts 是否已屏蔽：

```bash
for domain in apifox.it.com cdn.openroute.dev upgrade.feishu.it.com ns.feishu.it.com system.toshinkyo.or.jp; do
  grep -q "$domain" /etc/hosts && echo "PASS: $domain 已屏蔽" || echo "NEED: $domain 未屏蔽"
done
```

如有未屏蔽的域名，由于需要 sudo 权限，**必须输出命令文本让用户手动执行**：

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

用户确认完成后，**重新执行上述 grep 检查进行复验**，确保全部 PASS。

### 2.5 清理阶段小结

输出清理报告后，自动进入 Phase 3。

---

## Phase 3：凭证轮换

详细轮换流程参见 [apifox-credential-rotate]({baseDir}/../apifox-credential-rotate/SKILL.md)，以下为执行摘要。

> **核心原则：** 清理缓存 ≠ 消除威胁。攻击期间泄露的凭证仍被攻击者持有，必须逐一轮换。

### 3.1 扫描受影响凭证

全面扫描并生成资产清单。**扫描结果必须记录指纹，后续精准删除依赖于此。**

#### SSH 密钥

> **注意：** 必须通过 `bash -c` 执行。zsh 下 glob 无匹配会报错（`no matches found`）导致脚本中断。

```bash
bash -c '
for key in ~/.ssh/id_* ~/.ssh/*_rsa ~/.ssh/*_ed25519 ~/.ssh/*_ecdsa ~/.ssh/*_dsa; do
  [ -f "$key" ] || continue; [[ "$key" == *.pub ]] && continue
  pub="${key}.pub"
  fingerprint=$(ssh-keygen -lf "$pub" 2>/dev/null | awk "{print \$2}")
  comment=$(ssh-keygen -lf "$pub" 2>/dev/null | awk "{for(i=3;i<=NF;i++) printf \"%s \",\$i; print \"\"}")
  echo "密钥: $key | 指纹: $fingerprint | 备注: $comment"
done
'
```

```bash
# SSH Config 中密钥与 Host 的映射
grep -B5 "IdentityFile" ~/.ssh/config 2>/dev/null | grep -E "^Host |IdentityFile"
```

#### Git / K8s / Docker / npm

```bash
# Git
git config --global user.email 2>/dev/null
security find-internet-password -s "github.com" 2>/dev/null | grep -E "acct|srvr"
cat ~/.git-credentials 2>/dev/null || echo "无 git-credentials 文件"

# K8s
kubectl config get-contexts 2>/dev/null || echo "无 K8s 配置"

# Docker
cat ~/.docker/config.json 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -A1 "auths"

# npm
grep -iE "authToken|_auth|token" ~/.npmrc 2>/dev/null && echo "WARNING: 存在 npm token" || echo "OK: 无 npm auth token"
```

#### Shell 历史中的服务器和敏感信息

```bash
grep -oE 'ssh\s+\S+@\S+' ~/.zsh_history ~/.bash_history 2>/dev/null | sed 's/^.*:ssh //' | sort -u
```

#### 配置文件内嵌凭证（可选扫描）

> 以下文件未明确列入攻击窃取清单，但 Shell 历史和环境变量可能被间接泄露。仅作建议，由用户判断。

```bash
for f in ~/.zshrc ~/.bashrc ~/.bash_profile ~/.zprofile ~/.claude.json ~/.env ~/.env.local; do
  [ -f "$f" ] || continue
  hits=$(grep -inE 'password|passwd|token|secret|api.key|apikey|access.key|private.key|credential' "$f" 2>/dev/null | grep -v '^\s*#' | head -5)
  [ -n "$hits" ] && echo "--- $f ---" && echo "$hits" && echo ""
done
```

如果发现内嵌凭证，用 `AskUserQuestion` 展示具体文件和行号，说明风险级别（建议而非必须），由用户决定是否修改。

#### 输出要求

生成完整的资产清单表格，对无法判断关联平台的密钥**必须询问用户**：

| 凭证类型 | 具体项 | 指纹/标识 | 关联平台 | 状态 |
|----------|--------|-----------|----------|------|
| SSH 密钥 | `~/.ssh/id_ed25519_github` | `SHA256:xxxx` | GitHub | 待轮换 |
| SSH 密钥 | `~/.ssh/coding_net` | `SHA256:yyyy` | Coding | 待轮换 |
| SSH 密钥 | `~/.ssh/doc_manager_id_rsa` | `SHA256:zzzz` | **需用户确认** | 待确认 |
| K8s | <your-k8s-context> | - | 腾讯云 TKE | 待轮换 |
| Docker | <your-registry-host>:<port> | - | 私有 Registry | 待轮换 |
| 服务器 | root@<your-server-ip> | - | Shell 历史 | 建议改密码 |

### 3.2 选择清理方式

**必须用 `AskUserQuestion` 询问用户：**

```
凭证扫描完成。接下来需要在各平台删除旧密钥并部署新密钥，请选择操作方式：

1. **手动清理** -- 我逐平台给出操作指引和 URL，你自行在浏览器中操作
2. **Playwright MCP 辅助** -- 我通过浏览器自动化帮你操作（过程中需要你授权登录各平台）

请回复 1 或 2。
```

如果用户选择 Playwright MCP，先检查是否已安装：

```bash
claude mcp list 2>/dev/null | grep -i playwright
```

未安装时引导：

```
Playwright MCP 尚未安装。请执行以下命令安装：

! claude mcp add playwright -- npx @anthropic-ai/mcp-playwright@latest

安装完成后需要重启 Claude Code 生效。或者选择手动清理（选项 1）。
```

### 3.3 生成新密钥

在删除旧密钥之前先生成新密钥，文件名加 `_new` 后缀避免覆盖旧密钥：

```bash
# 根据扫描结果，为每个受影响的密钥生成替代
ssh-keygen -t ed25519 -C "user@email.com" -f ~/.ssh/id_ed25519_github_new
ssh-keygen -t ed25519 -C "user@email.com" -f ~/.ssh/coding_net_new
# ... 根据实际扫描结果生成
```

### 3.4 逐平台轮换

#### 逐项确认

**每一个凭证在轮换前，都必须使用 `AskUserQuestion` 向用户确认。** 用户可能已手动轮换，或判断风险可控选择不轮换（如测试账号资源少，轮换会产生大量非本地更新成本）。

确认格式：

```
接下来要轮换以下凭证：

  平台：GitHub
  密钥：~/.ssh/id_ed25519_github
  指纹：SHA256:xxxx

是否需要轮换？
1. 需要轮换
2. 已手动轮换，跳过
3. 不需要轮换（风险可控）
```

- 回复 1 -> 执行轮换
- 回复 2 -> 跳过操作，仍执行验证命令确认连通性
- 回复 3 -> 标记为"用户跳过（风险可控）"，记入最终报告

#### 精准删除原则

**不要删除所有密钥，只删除受影响的那一把。** 通过 3.1 记录的指纹在平台上精确匹配目标密钥。

#### SSH 密钥轮换平台指引

| 平台 | 密钥管理入口 | 操作步骤 | 验证命令 |
|------|-------------|----------|----------|
| GitHub | https://github.com/settings/keys | 按指纹找到目标密钥 > Delete > New SSH key 添加新公钥 | `ssh -T git@github.com` |
| GitLab | https://gitlab.com/-/user_settings/ssh_keys | 按指纹找到目标密钥 > Remove > Add new key | `ssh -T git@gitlab.com` |
| Tencent Coding | https://e.coding.net/user/account/setting/ssh | 按指纹找到目标密钥 > 删除 > 新增公钥 | `ssh -T git@e.coding.net` |
| Gitee | https://gitee.com/profile/sshkeys | 按指纹找到目标密钥 > 删除 > 新增公钥 | `ssh -T git@gitee.com` |
| Bitbucket | https://bitbucket.org/account/settings/ssh-keys/ | 按指纹找到目标密钥 > Remove > Add key | `ssh -T git@bitbucket.org` |
| 自有服务器 | 服务器上 `~/.ssh/authorized_keys` | SSH 登录 > 编辑 authorized_keys 删除匹配公钥行 > 追加新公钥 | `ssh user@server` |

> **欢迎用户补充更多平台到此表格。**

#### Git 凭证轮换

| 平台 | Token 管理入口 | 操作步骤 |
|------|---------------|----------|
| GitHub PAT | https://github.com/settings/tokens | 吊销旧 Token > Generate new token > 更新本地 |
| GitLab PAT | https://gitlab.com/-/user_settings/personal_access_tokens | 同上 |
| Coding PAT | https://e.coding.net/user/account/setting/tokens | 同上 |

macOS Keychain 更新：

```bash
security delete-internet-password -s "github.com" 2>/dev/null
# 下次 git push 时会提示重新输入
```

#### K8s 凭证轮换

| 集群类型 | 操作步骤 |
|----------|----------|
| 腾讯云 TKE | 腾讯云控制台 > 容器服务 > 集群 > 基本信息 > 重新获取 Kubeconfig |
| 阿里云 ACK | 阿里云控制台 > 容器服务 > 集群 > 连接信息 > 重新获取 Kubeconfig |
| 自建集群 | 重新签发客户端证书或 Token，更新本地 `~/.kube/config` |

```bash
# 验证
kubectl cluster-info && kubectl get nodes
```

#### Docker Registry 凭证轮换

```bash
# 登出后重新登录（根据扫描结果替换实际地址）
docker logout <registry-address>
docker login <registry-address>
```

#### Playwright MCP 辅助操作流程

如果用户选择 Playwright 辅助，按以下流程操作每个平台：

1. `browser_navigate` 打开平台密钥管理 URL
2. 提示用户在浏览器中完成登录，用 `browser_snapshot` 确认登录状态
3. `browser_take_screenshot` 截图，在密钥列表中定位与 3.1 指纹匹配的条目
4. **截图确认后**，`browser_click` 删除目标密钥
5. 填入新公钥内容并提交
6. 截图存档

> **重要：每一步关键操作（删除、提交）前都必须截图让用户确认，绝不自动跳过。**

### 3.5 服务器密码修改

Shell 历史中暴露的 SSH 连接目标，其密码建议修改：

- `.zsh_history` / `.bash_history` 可能泄露了服务器 IP、用户名、甚至明文密码
- 攻击者可据此进行横向移动

生成服务器清单后提示用户逐一处理：

| 服务器 | 用户 | 建议操作 |
|--------|------|----------|
| 根据扫描结果填充 | | 修改密码 + 建议禁用密码登录 |

建议加固（输出给用户参考，**附带警告**）：

```
# ⚠️ 执行前确保新 SSH 密钥已部署到服务器，否则会锁死自己
# 在服务器上执行：
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### 3.6 清理旧密钥

**所有平台验证通过后**，删除旧密钥并重命名新密钥。以注释形式输出命令，**必须让用户确认后再执行**：

```bash
# 用户确认后取消注释执行：
# rm ~/.ssh/id_ed25519_github ~/.ssh/id_ed25519_github.pub
# mv ~/.ssh/id_ed25519_github_new ~/.ssh/id_ed25519_github
# mv ~/.ssh/id_ed25519_github_new.pub ~/.ssh/id_ed25519_github.pub
```

---

## Phase 4：最终验证与报告

全部完成后，逐项验证并输出最终报告：

```bash
echo "=== SSH ===" && ssh -T git@github.com 2>&1; ssh -T git@e.coding.net 2>&1
echo "=== K8s ===" && kubectl cluster-info 2>/dev/null
echo "=== Docker ===" && docker info 2>/dev/null | grep "Registry"
echo "=== Hosts ===" && for d in apifox.it.com cdn.openroute.dev upgrade.feishu.it.com ns.feishu.it.com system.toshinkyo.or.jp; do grep -q "$d" /etc/hosts && echo "PASS: $d" || echo "FAIL: $d"; done
```

**最终报告格式：**

```
## ApiFox 供应链攻击修复报告

### 排查结果
- 感染状态：已确认中招
- ApiFox 版本：v2.8.20（已修复）

### 本地清理
| 清理项 | 状态 |
|--------|------|
| Local Storage/leveldb | 已清除 |
| Network Persistent State | 已清除 |
| Cache / Code Cache / Session Storage | 已清除 |
| C2 域名屏蔽 | 5/5 已屏蔽 |

### 凭证轮换
| 凭证类型 | 平台 | 旧密钥指纹 | 状态 |
|----------|------|-----------|------|
| SSH 密钥 | GitHub | SHA256:xxxx | 已轮换 / 已手动轮换 / 用户跳过（风险可控） |
| SSH 密钥 | Coding | SHA256:yyyy | 已轮换 |
| ... | ... | ... | ... |

### 服务器加固
| 服务器 | 状态 |
|--------|------|
| root@x.x.x.x | 已改密码 / 已禁用密码登录 |

修复完成时间：YYYY-MM-DD HH:MM
```

### 收尾：检查项目目录残留

轮换过程中可能在当前工作目录或项目目录内产生残留文件（截图、下载的 Kubeconfig、临时密钥文件等），这些文件如果被提交到 Git 仓库会造成二次泄露。**在生成最终报告前，必须扫描并清理。**

```bash
echo "=== 检查当前项目目录残留 ==="
# 轮换过程中的截图
find . -maxdepth 2 -name "*.png" -newer /Applications/Apifox.app 2>/dev/null
# 下载的 Kubeconfig 文件
find ~/Downloads -name "cls-*-config*" -newer /Applications/Apifox.app 2>/dev/null
# 旧密钥备份
ls ~/.ssh/*_old* ~/.ssh/*_failed* ~/.ssh/*_new* 2>/dev/null
# K8s 配置备份
ls ~/.kube/config.bak.* 2>/dev/null

echo ""
echo "=== 检查 git 未跟踪文件中是否有敏感内容 ==="
git status --short 2>/dev/null | grep -iE '\.pub$|\.pem$|config|key|credential|\.png$'
```

**处理原则：**
- 截图文件（如 `github-ssh-keys-before-delete.png`）：确认不再需要后删除，或加入 `.gitignore`
- 下载的 Kubeconfig：凭证已替换到 `~/.kube/config` 后删除下载文件
- `_old` / `_failed` / `_new` 后缀密钥：验证通过后删除
- K8s config 备份：验证通过后删除
- 如果项目目录有 `.gitignore`，确认以上文件类型已包含在忽略规则中

```bash
# 清理示例（需用户确认后执行）
# rm ./github-ssh-keys-before-delete.png ./github-ssh-add-new-key.png ./coding-ssh-page.png ./tencent-tke-clusters.png
# rm ~/Downloads/cls-*-config*
# rm ~/.ssh/*_old* ~/.ssh/*_failed*
# rm ~/.kube/config.bak.*
```

> **重要：** 清理前使用 `AskUserQuestion` 列出所有发现的残留文件，让用户确认哪些可以删除。不要自动删除任何文件。

---

## Windows / Linux（待补充）

> macOS 数据目录：`~/Library/Application Support/apifox/`
> Windows 数据目录：`%APPDATA%/apifox/`
> Linux 数据目录：`~/.config/apifox/`
>
> 清理和扫描逻辑一致，仅路径不同。欢迎社区贡献 PR。
