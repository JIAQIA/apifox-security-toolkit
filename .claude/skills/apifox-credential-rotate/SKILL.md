---
name: apifox-credential-rotate
description: 扫描本机受 ApiFox 供应链攻击影响的凭证（SSH 密钥、Git 凭证、K8s、Docker、服务器密码等），精准定位受影响资产，引导用户在各平台逐一轮换。支持用户手动操作或通过 Playwright MCP 辅助清理。
---

# ApiFox 供应链攻击 -- 凭证轮换

在 [apifox-security-check]({baseDir}/../apifox-security-check/SKILL.md) 确认中招、[apifox-security-clean]({baseDir}/../apifox-security-clean/SKILL.md) 清理本地残留后，执行本流程轮换所有可能泄露的凭证。

> **为什么必须轮换：** 攻击期间恶意代码会窃取 `~/.ssh/`、`~/.gitconfig`、Shell 历史、K8s 配置等，即使本地已清理，泄露的凭证仍可能被攻击者持有并用于远程访问。清理缓存 ≠ 消除威胁，轮换凭证才是根本。

## Step 1：扫描受影响凭证

全面扫描本机凭证，生成资产清单。扫描结果将在后续步骤中用于精准定位需要删除/替换的具体密钥。

### 1.1 SSH 密钥

> **注意：** 以下脚本必须通过 `bash -c '...'` 执行。zsh 下 glob 无匹配时会直接报错（`no matches found`）导致脚本中断，而 bash 会将无匹配的 glob 保留为字面量，由 `[ -f "$key" ] || continue` 安全跳过。

```bash
bash -c '
echo "=== SSH 密钥清单 ==="
for key in ~/.ssh/id_* ~/.ssh/*_rsa ~/.ssh/*_ed25519 ~/.ssh/*_ecdsa ~/.ssh/*_dsa; do
  [ -f "$key" ] || continue
  [[ "$key" == *.pub ]] && continue
  pub="${key}.pub"
  fingerprint=$(ssh-keygen -lf "$pub" 2>/dev/null | awk "{print \$2}")
  comment=$(ssh-keygen -lf "$pub" 2>/dev/null | awk "{for(i=3;i<=NF;i++) printf \"%s \",\$i; print \"\"}")
  echo "- 私钥: $key"
  echo "  公钥: $pub"
  echo "  指纹: $fingerprint"
  echo "  备注: $comment"
  echo ""
done
'
```

```bash
echo "=== SSH Config 密钥映射 ==="
# 解析 ~/.ssh/config，找出每个密钥关联的 Host
grep -B5 "IdentityFile" ~/.ssh/config 2>/dev/null | grep -E "^Host |IdentityFile"
```

**输出要求：** 生成结构化清单并记录，后续步骤需要用指纹精准匹配。示例：

| 密钥文件 | 指纹 | 关联平台 | 操作 |
|----------|------|----------|------|
| `~/.ssh/id_ed25519_github` | `SHA256:xxxx` | GitHub (github.com) | 待轮换 |
| `~/.ssh/coding_net` | `SHA256:yyyy` | Tencent Coding (e.coding.net) | 待轮换 |
| `~/.ssh/doc_manager_id_rsa` | `SHA256:zzzz` | 未知（需用户确认） | 待确认 |

对于无法从 SSH config 中判断关联平台的密钥，**必须询问用户**该密钥用于什么服务，以便后续精准删除。

### 1.2 Git 凭证

```bash
echo "=== Git 全局配置 ==="
git config --global user.name 2>/dev/null
git config --global user.email 2>/dev/null
git config --global credential.helper 2>/dev/null

echo ""
echo "=== macOS Keychain 中的 Git 凭证 ==="
security find-internet-password -s "github.com" 2>/dev/null | grep -E "acct|srvr|cdat"
security find-internet-password -s "e.coding.net" 2>/dev/null | grep -E "acct|srvr|cdat"

echo ""
echo "=== Git Credentials 文件 ==="
cat ~/.git-credentials 2>/dev/null || echo "无 ~/.git-credentials 文件"
```

### 1.3 K8s 凭证

```bash
echo "=== K8s Contexts ==="
kubectl config get-contexts 2>/dev/null || echo "kubectl 未安装或无配置"

echo ""
echo "=== K8s 集群列表 ==="
kubectl config get-clusters 2>/dev/null
```

### 1.4 Docker Registry 凭证

```bash
echo "=== Docker 认证配置 ==="
cat ~/.docker/config.json 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -A1 "auths" || echo "无 Docker 配置"
```

### 1.5 npm Token

```bash
echo "=== npm 配置 ==="
cat ~/.npmrc 2>/dev/null || echo "无 ~/.npmrc"
# 检查是否包含 auth token
grep -iE "authToken|_auth|token" ~/.npmrc 2>/dev/null && echo "WARNING: 存在 npm token" || echo "OK: 无 auth token"
```

### 1.6 Shell 历史敏感信息

```bash
echo "=== Shell 历史中的敏感记录 ==="
# 扫描可能泄露的服务器地址和凭证
grep -iE 'ssh\s+\S+@\S+|sshpass|mysql\s+-u|PGPASSWORD|token=|password=|apikey=|api.key=|secret=' \
  ~/.zsh_history ~/.bash_history 2>/dev/null | \
  sed 's/^.*:0;//' | sort -u
```

**输出要求：** 提取所有通过 SSH 连接过的服务器地址，这些服务器的密码也建议修改（因为历史记录可能包含密码或暴露了登录模式）。

### 1.7 配置文件中的内嵌凭证（可选扫描）

> **说明：** 以下配置文件目前没有明确列入本次攻击的窃取清单，但 Shell 历史和环境变量可能被间接泄露。此步骤仅作为建议，由用户判断是否需要处理。

扫描常见配置文件中是否内嵌了密码、Token、API Key 等敏感信息：

```bash
echo "=== 配置文件内嵌凭证扫描 ==="
for f in ~/.zshrc ~/.bashrc ~/.bash_profile ~/.zprofile ~/.claude.json ~/.env ~/.env.local; do
  [ -f "$f" ] || continue
  hits=$(grep -inE 'password|passwd|token|secret|api.key|apikey|access.key|private.key|credential' "$f" 2>/dev/null | grep -v '^\s*#' | head -5)
  if [ -n "$hits" ]; then
    echo ""
    echo "--- $f ---"
    echo "$hits"
  fi
done
echo ""
echo "扫描完成。如无输出则表示未发现内嵌凭证。"
```

**输出要求：** 如果扫描发现配置文件中包含明文密码或 Token，向用户展示具体文件和行号，并使用 `AskUserQuestion` 询问：

```
以下配置文件中发现了内嵌的敏感信息：

  文件：~/.claude.json
  内容：password=xxx（第 N 行）

这些文件目前没有明确列入本次攻击的窃取文件清单，但 Shell 历史和环境变量可能被间接泄露。
是否需要修改其中的密码/Token？

1. 需要修改
2. 不需要（我自行判断风险）
```

如果用户选择修改，逐文件引导用户更新对应的密码或 Token 值。

## Step 2：确认清理方式

扫描完成后，**必须询问用户**选择清理方式：

```
凭证扫描完成，接下来需要在各平台删除旧密钥并部署新密钥。

请选择清理方式：

1. **手动清理** -- 我会逐平台给出操作指引和 URL，你自行在浏览器中操作
2. **Playwright MCP 辅助清理** -- 我通过浏览器自动化帮你操作（需要你在过程中授权登录各平台）

请回复 1 或 2。
```

如果用户选择 2（Playwright MCP），先检查是否已安装：

```bash
# 检查 Playwright MCP 是否可用
claude mcp list 2>/dev/null | grep -i playwright
```

如果未安装，引导用户安装：

```
Playwright MCP 尚未安装，需要先添加才能使用浏览器辅助功能。
请执行以下命令安装：

! claude mcp add playwright -- npx @anthropic-ai/mcp-playwright@latest

安装完成后需要重启 Claude Code 生效。
或者你也可以选择手动清理（选项 1），无需安装。
```

## Step 3：生成新密钥

采用**先备份旧密钥、生成新密钥、平台替换、验证、再清理**的安全流程，确保任何环节出错都可回滚。

### 3.1 备份旧密钥

```bash
# 将旧密钥重命名为 _old 后缀，保留回滚能力
mv ~/.ssh/id_ed25519_github ~/.ssh/id_ed25519_github_old
mv ~/.ssh/id_ed25519_github.pub ~/.ssh/id_ed25519_github_old.pub
```

### 3.2 生成新密钥

```bash
# 直接生成到最终文件名（旧密钥已备份，不会冲突）
ssh-keygen -t ed25519 -C "your_email@example.com" -f ~/.ssh/id_ed25519_github -N ""
```

### 3.3 在平台上替换（Step 4 详述）

在对应平台删除旧公钥、添加新公钥。

### 3.4 验证连通性

```bash
ssh -T git@github.com 2>&1
# 预期：Hi xxx! You've successfully authenticated
# 注意：exit code 1 是正常的，GitHub 不提供 shell access
```

### 3.5 验证通过后清理旧密钥

```bash
# 验证通过后删除旧密钥
rm ~/.ssh/id_ed25519_github_old ~/.ssh/id_ed25519_github_old.pub
```

### 3.6 验证失败时回滚

```bash
# 如果新密钥不工作，立即回滚
mv ~/.ssh/id_ed25519_github ~/.ssh/id_ed25519_github_failed
mv ~/.ssh/id_ed25519_github_old ~/.ssh/id_ed25519_github
mv ~/.ssh/id_ed25519_github_old.pub ~/.ssh/id_ed25519_github.pub
```

> **原则：旧密钥在验证通过前绝不删除。** 每个平台独立执行 备份->生成->替换->验证->清理 的完整周期，不要批量操作。

## Step 4：逐平台轮换凭证

### 逐项确认原则

**每一个凭证在轮换前，都必须使用 `AskUserQuestion` 向用户确认是否需要轮换。** 用户可能：
- 已经在某个平台手动完成了轮换
- 判断某个凭证风险可控，主动选择不轮换（如测试账号资源极少，轮换会产生大量非本地更新成本）

确认提问格式：

```
接下来要轮换以下凭证：

  平台：GitHub
  密钥：~/.ssh/id_ed25519_github
  指纹：SHA256:xxxx

是否需要轮换？
1. 需要轮换
2. 已手动轮换，跳过
3. 不需要轮换（风险可控）

请回复 1、2 或 3。
```

- 回复 1 -> 执行轮换流程
- 回复 2 -> 标记为"已手动轮换"，跳过操作，但仍执行验证命令确认连通性
- 回复 3 -> 标记为"用户跳过（风险可控）"，记入最终报告

### 精准删除原则

**关键：不要删除所有密钥，只删除受影响的那一把。** 用户可能在同一平台配置了多把密钥（不同设备/用途），需要通过 Step 1 记录的指纹精准匹配：

1. 在平台上找到与 Step 1 记录的指纹匹配的密钥
2. 仅删除该密钥
3. 添加新生成的公钥
4. 测试连通性

### 平台操作指引

以下表格列出常见平台的密钥管理入口和操作方法。**欢迎用户补充更多平台。**

#### SSH 密钥轮换

| 平台 | 密钥管理入口 | 操作步骤 | 验证命令 |
|------|-------------|----------|----------|
| GitHub | Settings > SSH and GPG keys | 1. 找到与指纹匹配的密钥删除 2. 点击 "New SSH key" 添加新公钥 | `ssh -T git@github.com` |
| | https://github.com/settings/keys | | |
| GitLab | Preferences > SSH Keys | 1. 找到匹配指纹的密钥删除 2. 点击 "Add new key" | `ssh -T git@gitlab.com` |
| | https://gitlab.com/-/user_settings/ssh_keys | | |
| Tencent Coding | 个人设置 > SSH 公钥 | 1. 找到匹配指纹的密钥删除 2. 点击 "新增公钥" | `ssh -T git@e.coding.net` |
| | https://e.coding.net/user/account/setting/ssh | | |
| Gitee | 设置 > SSH 公钥 | 1. 找到匹配指纹的密钥删除 2. 点击 "新增公钥" | `ssh -T git@gitee.com` |
| | https://gitee.com/profile/sshkeys | | |
| Bitbucket | Personal settings > SSH keys | 1. 找到匹配指纹的密钥删除 2. 点击 "Add key" | `ssh -T git@bitbucket.org` |
| | https://bitbucket.org/account/settings/ssh-keys/ | | |
| 自有服务器 | `~/.ssh/authorized_keys` | 1. SSH 登录服务器 2. 编辑 authorized_keys 删除匹配的公钥行 3. 添加新公钥 | `ssh user@server` |

#### Git 凭证轮换

| 平台 | Token 管理入口 | 操作步骤 |
|------|---------------|----------|
| GitHub PAT | https://github.com/settings/tokens | 1. 吊销旧 Token 2. 生成新 Token 3. 更新本地 Keychain |
| GitLab PAT | https://gitlab.com/-/user_settings/personal_access_tokens | 同上 |
| Coding PAT | https://e.coding.net/user/account/setting/tokens | 同上 |

macOS Keychain 中的 Git 凭证更新：

```bash
# 删除旧的 Keychain 条目
security delete-internet-password -s "github.com" 2>/dev/null

# 下次 git push 时会提示重新输入，自动存入新凭证
```

#### K8s 凭证轮换

K8s Kubeconfig 轮换需要在云平台控制台操作，遵循**备份->下载->比对->替换->验证**的流程。

**第一步：备份旧配置**

```bash
cp ~/.kube/config ~/.kube/config.bak.$(date +%Y%m%d)
```

**第二步：在云平台吊销旧证书并获取新 Kubeconfig**

| 集群类型 | 操作步骤 |
|----------|----------|
| 腾讯云 TKE | 控制台 > 容器服务 > 集群详情 > 基本信息 > 集群APIServer信息 > **关闭**外网/内网访问端点 > 等待几秒后**重新开启** > 下载新 Kubeconfig |
| 阿里云 ACK | 控制台 > 容器服务 > 集群 > 连接信息 > 吊销并重新生成 Kubeconfig |
| 自建集群 | 重新签发客户端证书或 Token |

> **关键：** 必须先**关闭**再**重新开启**端点，而非直接重新下载。仅重新下载会得到同一份旧证书。关闭再开启会吊销旧证书并签发新证书。

**第三步：验证新旧证书确实不同**

```bash
# 用 MD5 比较证书内容，不要只比较前几十个字符（base64 头部结构可能相同导致误判）
echo "=== 旧证书 ===" && kubectl config view --raw -o jsonpath='{.users[?(@.name=="USER_NAME")].user.client-certificate-data}' | md5
echo "=== 新证书 ===" && kubectl config --kubeconfig="新下载的文件" view --raw -o jsonpath='{.users[0].user.client-certificate-data}' | md5
# 两个 MD5 必须不同，否则证书未真正轮换
```

**第四步：逐字段替换**（不要直接覆盖整个 config，因为可能包含多个集群）

```bash
# 更新 server 地址（关闭再开启后 IP 可能变化）
kubectl config set-cluster CLUSTER_NAME --server=NEW_SERVER_URL

# 更新 CA、客户端证书和密钥
kubectl config set clusters.CLUSTER_NAME.certificate-authority-data "NEW_CA_DATA"
kubectl config set users.USER_NAME.client-certificate-data "NEW_CERT_DATA"
kubectl config set users.USER_NAME.client-key-data "NEW_KEY_DATA"
```

从新文件中提取各字段的方法：

```bash
kubectl config --kubeconfig="新文件" view --raw -o jsonpath='{.clusters[0].cluster.server}'
kubectl config --kubeconfig="新文件" view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}'
kubectl config --kubeconfig="新文件" view --raw -o jsonpath='{.users[0].user.client-certificate-data}'
kubectl config --kubeconfig="新文件" view --raw -o jsonpath='{.users[0].user.client-key-data}'
```

**第五步：验证连通性**

```bash
kubectl --context=CONTEXT_NAME get nodes
# 预期：显示节点列表，状态 Ready
```

**第六步：清理多余 context**

如果合并过程中产生了重复的 context（如 `cls-xxx-yyy-context-default`），清理掉只保留别名：

```bash
kubectl config delete-context 多余的context名
```

**第七步：验证通过后删除备份**

```bash
rm ~/.kube/config.bak.$(date +%Y%m%d)
```

> **回滚：** 验证失败时直接恢复备份 `cp ~/.kube/config.bak.YYYYMMDD ~/.kube/config`

#### Docker Registry 凭证轮换

```bash
# 登出所有 Registry
docker logout <your-registry-host>:<port>
docker logout <your-registry-domain>

# 重新登录（会提示输入新密码）
docker login <your-registry-host>:<port>
docker login <your-registry-domain>
```

### Playwright MCP 辅助操作流程

如果用户选择了 Playwright MCP 辅助清理，按以下流程操作：

1. **导航到密钥管理页面**：使用 `mcp__plugin_playwright_playwright__browser_navigate` 打开对应平台 URL
2. **等待用户登录**：提示用户在浏览器中完成登录授权，使用 `mcp__plugin_playwright_playwright__browser_snapshot` 确认登录状态
3. **截图确认**：操作前使用 `mcp__plugin_playwright_playwright__browser_take_screenshot` 截图，确认当前页面内容
4. **精准定位目标密钥**：在密钥列表中查找与 Step 1 记录的指纹匹配的条目
5. **删除旧密钥**：使用 `browser_click` 点击删除按钮，**每次删除前都要截图确认**，避免误删
6. **添加新公钥**：将新生成的公钥内容填入表单
7. **截图存档**：操作完成后截图，作为轮换记录

> **重要：** Playwright 操作过程中，每一步关键操作（删除、提交）前都必须截图让用户确认，绝不自动跳过确认步骤。

## Step 5：服务器密码修改

Shell 历史中发现的 SSH 连接目标服务器，其密码建议修改。因为 `.zsh_history` / `.bash_history` 可能泄露了：
- 服务器 IP 和用户名（暴露攻击面）
- 明文密码（`sshpass -p` 等命令）
- 内部服务地址和端口

```bash
# 从 Step 1.6 的扫描结果中提取服务器列表
grep -oE 'ssh\s+\S+@\S+' ~/.zsh_history ~/.bash_history 2>/dev/null | \
  sed 's/^.*:ssh //' | sort -u
```

**输出要求：** 生成服务器清单，提示用户逐一修改密码：

| 服务器 | 用户 | 建议操作 |
|--------|------|----------|
| `root@<your-server-ip>` | root | 修改密码 + 禁用密码登录，改用新 SSH 密钥 |
| ... | ... | ... |

建议同时加固服务器配置：

```bash
# 在服务器上执行：禁用密码登录，仅允许密钥认证
# sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
# sudo systemctl restart sshd
```

> **注意：** 修改 sshd_config 前确保新密钥已部署到服务器，否则会锁死自己。向用户输出此命令文本时必须附带此警告。

## Step 6：验证与报告

全部轮换完成后，逐项验证并生成最终报告：

```bash
echo "=== SSH 连通性验证 ==="
ssh -T git@github.com 2>&1
ssh -T git@e.coding.net 2>&1

echo ""
echo "=== K8s 集群验证 ==="
kubectl cluster-info 2>/dev/null

echo ""
echo "=== Docker Registry 验证 ==="
docker info 2>/dev/null | grep "Registry"
```

**最终输出报告格式：**

```
## 凭证轮换报告

| 凭证类型 | 平台 | 旧密钥指纹 | 状态 |
|----------|------|-----------|------|
| SSH 密钥 | GitHub | SHA256:xxxx | 已轮换 / 已手动轮换 / 用户跳过（风险可控） |
| SSH 密钥 | Coding | SHA256:yyyy | 已轮换 / 已手动轮换 / 用户跳过（风险可控） |
| Git PAT | GitHub | - | 已轮换 / 不适用 |
| K8s | <your-k8s-context> | - | 已轮换 / 用户跳过（风险可控） |
| Docker | <your-registry-host>:<port> | - | 已轮换 / 用户跳过（风险可控） |
| 服务器密码 | <your-server-ip> | - | 已修改 / 用户跳过（风险可控） |

轮换完成时间：YYYY-MM-DD HH:MM
```

最后，清理旧密钥文件（仅在 Step 3 中各平台验证全部通过后执行）：

```bash
# 删除备份的旧密钥（_old 后缀文件）
rm ~/.ssh/id_ed25519_github_old ~/.ssh/id_ed25519_github_old.pub
# 删除 K8s 备份
rm ~/.kube/config.bak.*
```

> **注意：** 清理前必须使用 `AskUserQuestion` 确认用户已完成所有平台的验证。旧密钥在验证通过前绝不删除。如果已废弃的平台（如已停运的 Coding），密钥和 SSH config 配置可以直接删除。
