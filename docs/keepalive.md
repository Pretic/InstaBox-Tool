# 机器保活说明

**InstaBox Tool 0.0.1 · 作者：Pre** · [返回首页](../README.md) · [使用手册](usage.md)

首次安装会通过 InstaBox API 为本机配置保活。日常由后台定时任务更新活动租约，退出菜单后仍会继续执行。一个控制端可维护一台或多台机器，无需机器之间互相连接。

## 配置目标

进入 **4「机器保活」**，按需要选择：

| 需求 | 菜单或命令 |
| --- | --- |
| 为当前机器配置保活 | `ibt keepalive auto-local`，首次安装已自动执行 |
| 加入所有运行中的机器 | **1 一键保活机器**，或 `ibt keepalive auto` |
| 手动选择一台或多台 | **2 管理保活目标 → 1 选择云端机器**，或 `ibt keepalive add-api` |
| 输入 SSH/Mosh 连接命令 | **2 管理保活目标 → 2 添加命令机器**，或 `ibt keepalive add` |

一键保活会查询当前授权可见的全部机器，把本次处于运行状态的机器加入目标，保留已有 API、SSH 和凭据换新配置。它不会启动暂停或停止的机器，也不会每轮自动纳入新机器；之后创建或启动机器，再执行一次即可。

自动识别本机使用 hostname 与平台机器名称的唯一匹配；无法确定时只选择一台，不凭账号内机器数量推测本机。手动选入的暂停或停止目标显示为待启动，机器运行后再维护。

### 控制端需要持续运行

后台任务运行在安装工具的机器上。控制端被暂停、停止或断网后无法继续发送保活请求；控制端本身已经暂停时，需要从 Dashboard 或独立控制端恢复。

也可以在独立、常在线的 Linux 机器上只安装管理工具，再选择目标：

```bash
export PATH="$HOME/.local/bin:$PATH" && bash <(curl -fsSL https://raw.githubusercontent.com/Pretic/InstaBox-Tool/main/setup.sh) --menu-only
ibt keepalive add-api
```

这种安装同样先验证 API Key。它不部署节点，其他环境要求与[标准安装](usage.md#安装)相同。

## 看懂保活状态

保活菜单显示摘要与目标列表，选择 **7「查看保活详情」** 展开每台机器的结果。命令行使用：

```bash
ibt keepalive status
```

| 字段 | 含义 |
| --- | --- |
| 自动保活 | 本机定时器是否启用、是否已配置开机启动 |
| 最近完成 | 最近一整轮检查结束的时间，不代表每个目标都成功 |
| 下次执行 | 从 systemd 读取的下一次计划时间 |
| 检查间隔 | 本轮完成后，到下一轮开始前的基本等待时间 |
| 最近成功 | 对应目标最近一次成功的时间 |
| 本轮有效 | API 成功返回的本轮活动有效期 |
| 授权到期／预计到期 | SSH token 的平台期限／手工估计期限 |

任务正在运行时，下次计划可能要等本轮结束后才能确定；停用、尚未排定或无法读取时会直接说明，不用估算时间替代真实计划。各目标的错误和有效期在详情中逐台显示。

时间默认跟随控制端时区，可运行 `ibt timezone set Asia/Shanghai` 修改工具显示。机器总览中的“本机保活”描述本控制端的配置与任务状态，不能据此推断其他控制端的任务。

## 管理后台任务

| 操作 | 命令 |
| --- | --- |
| 立即执行一轮 | `ibt keepalive run` |
| 启用后台任务 | `ibt keepalive start` |
| 停止后台任务 | `ibt keepalive stop` |
| 查看日志 | `ibt keepalive logs` |
| 移除指定目标 | `ibt keepalive remove` |
| 停用并清除本地保活配置 | `ibt keepalive clear` |

添加目标会启用自动任务。默认在每轮完成约 300 秒后执行下一轮，并有最多 15 秒调度抖动；无需反复手动执行 `run`。

停止、移除或清理时，工具会释放本控制端对应的 API 租约；请求失败时，租约按自身期限自然失效，不会被当作已经释放。停止任务不会关机，也不会撤销 API Key。

`stop` 保留当前 SSH 凭据和待验证记录，`clear` 清除本地保活与换新记录；二者都不会撤销云端 SSH token。若需要启动、暂停或停止机器，进入 **5「机器管理」**，参阅[机器管理](usage.md#机器管理)。

## SSH/Mosh 命令

API 保活之外，也可独立加入平台给出的连接命令：

```bash
ibt keepalive add
```

在隐藏输入中粘贴完整命令，例如：

```text
mosh --ssh="ssh -p 2222" ibssh_…@api.instabox.sh
```

上面的省略号仅表示示例，请使用自己的完整命令。工具提取 SSH 连接参数执行固定探测，不执行粘贴内容中的任意 Shell 命令，也不需要安装 Mosh。普通 SSH 保活模式本身不依赖 API Key；首次安装工具仍需完成 API 授权。

连接成功只能说明本轮 SSH 探测完成，是否持续满足平台的闲置活动判定，需要结合机器实际状态观察。`ibssh_...` 是不透明凭据，无法从字符串推算真实到期时间；手动填写的预计剩余小时只用于提醒。

未开启自动换新时，在 Dashboard 生成新连接命令，再运行 `ibt keepalive renew` 替换。手动换成不同 token 后，需要重新配置它的机器绑定和自动换新。

### 自动换新 SSH token

```bash
ibt keepalive rotate-setup
ibt keepalive token-status
```

选择已有 SSH 目标，明确绑定对应的云端机器，再配置有效期与提前量。该功能共用保存的 InstaBox API Key，需要 `machines:write` 权限；默认申请 24 小时 token，提前 1 小时换新。

后台调用官方接口创建替代 token，先验证新 token 能完成 SSH 探测，再更新本地目标并记录平台返回的到期时刻。它创建的是新凭据，原 token 的期限保持不变。[官方 SSH 说明](https://instabox.sh/docs/ssh)

| 情况 | 处理方式 |
| --- | --- |
| 新 token 已取得，但 SSH 验证失败 | 保留当前凭据，后续重试已保存的新 token |
| 创建请求超时、断线，结果未知 | 暂停自动重复创建，显示待处理状态 |
| 平台返回的期限已过或过短 | 保留当前凭据，提示调整配置或检查平台 |
| API Key 失效或权限不足 | 显示授权错误；用 `ibt key set` 更新授权 |
| 控制端停机或长时间断网 | 恢复运行后处理；停机期间无法自动换新 |

签发接口不是幂等接口，结果未知时重发可能创建额外凭据。需要人工继续时，用 `ibt keepalive rotate-now`，按提示确认；用 `ibt keepalive rotate-off` 停用周期换新。工具会检查提前量是否足以覆盖调度间隔，配置不满足时要求调整。[接口定义](https://api.instabox.sh/v1/openapi.json)

换新只更新工具内部保存的连接命令，电脑上此前复制的 Mosh 命令仍会按原期限失效。长时间未登录后，可在网页创建新连接命令进入机器，再更新工具中的凭据或 API Key。工具不会主动撤销旧 token，以免中断仍在使用它的会话。

## API 保活如何工作

后台对已配置目标定期调用官方活动租约接口：

```http
PUT /v1/machines/{id}/activity-leases/{leaseID}
Content-Type: application/json

{"ttlSeconds": 900}
```

每个控制端使用自己的租约 ID，周期更新同一租约。TTL 为 `max(900, interval × 3)` 秒；默认检查间隔 300 秒，对应 15 分钟租约。官方允许 30–3600 秒，配置间隔时也须满足 TTL 上限。[OpenAPI 定义](https://api.instabox.sh/v1/openapi.json)

有效租约用于维持任务活动，并可按平台规则唤醒因闲置自动暂停的机器。它不取消手动暂停、停止、运行超时、归档或回收规则；后台也不会在失败后用启动接口覆盖这些状态。读取机器状态、维持 TCP 连接或发送普通 SSH keepalive，不能直接等同于平台认可的活动。[生命周期说明](https://instabox.sh/docs/api/lifecycle#start)

### 授权与平台策略

API Key 在本机保存一次，供云端操作、API 保活和可选的 token 换新共用。Restricted Key 的 `machines:write` 包含机器读取权限；密钥有效性、机器可见范围和写权限分别由实际接口校验。密钥过期或撤销后，用 `ibt key set` 更新。[授权说明](https://instabox.sh/docs/keys-sdk)

日常 API 保活不要求关闭平台空闲暂停。**平台高级选项**中的 `ibt keepalive apply` 用于请求调整策略，`ibt keepalive check` 用于读回有效配置。请求成功不代表平台已允许关闭暂停；实际生效值取决于账号权限与平台规则。[机器配置说明](https://instabox.sh/docs/machines)

空闲暂停、运行超时和归档是不同的限制。查看 `ibt cloud account`、机器详情与有效配置，再根据平台返回决定操作。

## 检查是否持续生效

1. 运行 `ibt keepalive status`，确认目标、自动任务和下次执行时间；API 目标应有本轮成功记录及租约期限。
2. 用 `ibt keepalive run` 主动检查一轮，再观察后续自动执行，确认成功时间与租约到期时间持续更新。
3. 观察跨过机器实际空闲阈值后的状态，记录期间是否有终端、浏览器、端口访问等其他活动，以免把它们的效果归给脚本。
4. 若仍暂停，查看平台记录的原因、有效策略和本机日志，分别排查控制端中断、授权失效、目标错误或其他生命周期限制。

多个目标分别记录结果，一个目标失败不会被其他目标的成功掩盖。手动点击暂停属于明确的生命周期操作，不能用它模拟闲置暂停，再要求后台自动撤销。

排查时可保留目标名称、状态、时间和错误信息；不要公开 API Key、SSH token 或完整节点链接。

## 官方参考

- [API Keys 与 SDK](https://instabox.sh/docs/keys-sdk)
- [OpenAPI：活动租约、SSH tokens、机器与操作](https://api.instabox.sh/v1/openapi.json)
- [机器生命周期](https://instabox.sh/docs/api/lifecycle#start)
- [SSH 与 Mosh](https://instabox.sh/docs/ssh)
