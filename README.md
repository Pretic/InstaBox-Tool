# InstaBox Tool

**版本：0.0.1**

在 InstaBox 上一键安装 **sing-box + Cloudflare Quick Tunnel**，自动配置本机保活。安装后输入 `ibt`，通过中文菜单管理节点、云端机器和系统设置。

> [!IMPORTANT]
> **节点格式只有 VLESS + WebSocket（WS）+ TLS**，导出为 `vless://` 链接，默认节点名为 **IBT-Quick**。
>
> 默认使用 **Cloudflare 临时隧道（Quick Tunnel）**，无需自备域名。**机器完整重启或隧道重建后，临时域名和节点链接会变化**；运行 `ibt show` 获取当前链接，重新导入客户端。
>
> **需要长期固定的节点链接，请配置固定隧道并绑定自己的域名。** 入口为「节点管理 → 管理域名隧道」，详见[固定域名说明](docs/usage.md#固定域名)。[Cloudflare 官方说明](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)

## 开始使用

### 1. 准备 API Key

首次安装前，先创建一个 InstaBox 官方 API Key，供脚本进行保活和云端管理：

1. 登录 [InstaBox Dashboard](https://dashboard.instabox.sh/)。
2. 左侧选择 **API Keys**，右侧点击 **Create Key**。
3. 填写名称并选择权限：**Full access** 可使用；选择 **Restricted** 时授予 `machines:write`，已包含读取机器权限。
4. 按需设置有效期。**不选择到期日期表示不自动过期**，仍可在控制台撤销。[接口说明](https://api.instabox.sh/v1/openapi.json)
5. 创建后复制 `ibk_...` 密钥，安装时按提示粘贴。**密钥只显示一次，请妥善保存，勿对外泄露。**

若控制台要求先完成账号开通，按页面提示处理，并确认账号能访问要部署的机器。[官方说明](https://instabox.sh/docs/keys-sdk)

### 2. 在目标机器安装

启动要部署的 InstaBox 机器，打开其**网页端 Terminal**；也可按[本地 SSH 登录](#本地-ssh-登录推荐)说明，通过 **PowerShell 连接机器**后操作。

在机器的 Linux 终端中，以**普通用户**执行下方命令，不要加 `sudo`。需要 Linux x86_64、Python 3 和可用的用户级 systemd。

```bash
export PATH="$HOME/.local/bin:$PATH" && bash <(curl -fsSL https://raw.githubusercontent.com/Pretic/InstaBox-Tool/main/setup.sh)
```

按提示粘贴 API Key 并回车，**输入时不显示字符**。验证通过后，安装器自动完成：

1. 安装节点和临时隧道，生成 **IBT-Quick** 链接。
2. 识别**当前机器**并开启后台 API 保活；无法确定本机时，按列表选择当前这一台。
3. 检查结果并打开管理菜单。未完成的步骤会显示处理提示。

复制完整的 `vless://` 链接导入客户端，即可进行连接测试。

**部署范围：节点安装在当前登录的这台机器上，首次安装也只为本机配置保活。** 需要保活其他已开机机器时，进入「机器保活 → 一键保活机器」；该功能不会自动启动暂停或停止的机器。

### 3. 打开管理菜单

```bash
ibt
```

输入编号后回车选择功能，`0` 返回或退出。退出菜单后，已启用的节点和保活任务继续运行。

| 菜单 | 可以做什么 |
| --- | --- |
| 1 本机信息 | 查看系统、资源、网络和显示时区 |
| 2 查看节点 | 复制当前节点链接 |
| 3 节点管理 | 修复节点、管理隧道、查看日志、CF 优选 |
| 4 机器保活 | 一键保活、管理目标与自动任务、SSH 凭据换新 |
| 5 机器管理 | 查看全部机器，启动、暂停、停止及管理授权 |
| 6 机器优化 | 管理 Swap、BBR + fq，恢复设置 |
| 7 更新卸载 | 更新工具或卸载 |
| 0 退出菜单 | 退出当前菜单 |

## 常用操作

| 需要做什么 | 命令或入口 |
| --- | --- |
| 查看节点链接 | `ibt show` |
| 一键保活运行中的机器 | **4 机器保活 → 1 一键保活机器**，或 `ibt keepalive auto` |
| 查看保活结果和下次执行时间 | `ibt keepalive status` |
| 生成 CF 优选链接 | **3 节点管理 → 8 优选节点地址**，或 `ibt cf` |
| 更换 API Key | `ibt key set` |
| 更新工具 | `ibt update`，完成后重新输入 `ibt` |

一键保活会加入当前授权可见的运行中机器；想手动选择几台，进入 **机器保活 → 管理保活目标**。添加 SSH/Mosh 命令、固定域名、时区和系统优化的用法见[使用手册](docs/usage.md)。

## 本地 SSH 登录（推荐）

可选用本地 **PowerShell** 连接 InstaBox，登录后即可安装和使用脚本：

1. 登录 [InstaBox Dashboard](https://dashboard.instabox.sh/)，左侧选择 **Machines**。
2. 点击要连接的机器，确认已启动，打开页面右上方的 **Details**。
3. 在下方点击 **Create token**，填写名称、选择有效时长，再点击 **Create token**。**SSH token 最长有效期为 30 天。** [官方接口说明](https://api.instabox.sh/v1/openapi.json)
4. 复制上方**以 `ssh` 开头的完整连接命令**。命令中包含 SSH token，**仅显示一次，请妥善保存，勿对外泄露**。
5. 打开本地 PowerShell，粘贴该命令并回车。连接成功、进入远端 Linux 终端后，再执行上方的一键安装命令；已安装则输入 `ibt`。

SSH 命令格式如下，实际请使用控制台生成的完整内容：

```powershell
ssh -p 2222 ibssh_...@api.instabox.sh
```

**API Key 用于脚本授权和保活；SSH token 包含在连接命令中，用于登录对应机器。** SSH token 到期后，可在网页重新创建并复制新命令。[官方 SSH 说明](https://instabox.sh/docs/ssh)

## 使用提示

- **节点连接异常**时运行 `ibt diagnose`；需要重新创建临时隧道时运行 `ibt refresh-quick`，随后重新导入当前链接。
- **API Key 和节点链接请勿公开。** 隐藏输入框中粘贴后按回车即可。
- **保活需要控制端持续运行。** 它通过后台定时任务执行；控制端已暂停时，需要从控制台恢复。机制与状态说明见[保活说明](docs/keepalive.md)。

## 感谢

- **老王**：[eooce/Sing-box](https://github.com/eooce/Sing-box)
- **Joey**：[byJoey/cfy](https://github.com/byJoey/cfy)

## 友链

[Linux DO](https://linux.do)
