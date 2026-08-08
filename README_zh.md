# ParaEGOX

ParaEGOX 是一个面向机器人与具身智能体的分布式 Agent OS，目前正在从零重构。

ParaEGOX 基于 [PhanthyMotus](https://github.com/4paradigm/phanthymotus) 构建。原始基线保留在 `archive/phanthymotus-baseline` 分支，并保留其许可证归属。

> 当前状态：当前工作树已有首个 DeveloperLocal 后端、Textual 对话组合和 typed 单次 Inspection
> 启动视图。原生 Intel macOS r29 artifact run `31238285076` 已通过真实可搬移 bundle 的 Inspection、
> Runtime Agent IPC、Echo、Textual Ctrl-C、terminal restoration 和父进程 joined shutdown。Textual
> 现在是唯一 DeveloperLocal 展示路径；旧 Rust reference frontend 已删除。Ubuntu r33 commit
> `7618f6a51c5eb5731874d2cdf3231603e3a824f7` 还验证了公开 G1 host-local
> `paraegox node` 系统基座。生产核心机制优先采用 Rust，Python/C++ 作为受管工作负载与生态语言，
> 暂未提供稳定版本。

## 当前可运行切片

`paraegox` binary 会沿真实 owner 链启动 Authority、DeploymentController、Runtime，以及由 Runtime
管理的 Zenoh Fabric、ModelService、AgentService；同时启动独立 NodeDaemon reference child、
owner-private Agent/Inspection IPC 和内部 Python Textual child。Runtime 按 Fabric → Model → Agent
启动，只有精确、已签名的 PXMT ActiveReady 回执持久提交后才发放对话能力。

公开对话入口只有一个：

```text
paraegox chat --config <absolute-paraegox.toml>
```

provider、model、state root 和 Fabric listener 由 strict versioned TOML 配置选择，不是 provider 专属
子命令或 override flags。Secret value 不得进入配置或 argv，配置只保存精确 SecretRef。Chat 配置的
无凭据示例是 [`configs/paraegox.example.toml`](configs/paraegox.example.toml)；它当前选择 DeepSeek
作为可替换验证后端，不表示 CLI mode 或默认模型。

Textual child 由仓库中的 Python project 安装。开发工作树启动 `paraegox` 前，先准备并激活 locked
environment；若内部 `paraegox-console` executable 不存在，Rust parent 会直接失败，不会暗中回退到
另一套 frontend 或 transport：

```zsh
uv sync --locked
source .venv/bin/activate
command -v paraegox-console
```

`paraegox-console` 只是内部 packaging，不是第二个公开对话命令。macOS 请保留示例中的 canonical
`/private/tmp` state root（`/tmp` 是 symlink，会被安全校验拒绝）。macOS CI artifact 包含一个
SHA-256 校验的 `tar.gz`；解包前必须用相邻的 `.sha256` 文件验证。解包后的可搬移目录同级包含
`paraegox`、可执行的 `paraegox-console`，以及 `python/` 下的 vendored packages；三者必须保持在一起，
并保证 `PATH` 中有 Python 3.11 或更高版本的 `python3`。验证配置中的 DeepSeek 路径时，通过进程环境
提供它引用的 Secret，并传入配置的绝对路径：

```zsh
read -s 'DEEPSEEK_API_KEY?DeepSeek API key: '; echo
export DEEPSEEK_API_KEY
CONFIG_PATH="$(pwd)/configs/paraegox.example.toml"
PARAEGOX_BIN=/absolute/path/to/native/paraegox
test -x "$PARAEGOX_BIN"
"$PARAEGOX_BIN" chat --config "$CONFIG_PATH"
unset DEEPSEEK_API_KEY
```

原生 binary 必须在指定服务器或 GitHub CI 构建，Mac 只下载完整 bundle；当前工作流禁止在 Mac 运行
Cargo。

历史 Ubuntu r22 源码快照 `ff2d8109` 已通过 workspace format、locked metadata 和 locked
all-targets check，并通过 Inspection 39/39、非 root DeveloperLocal 89/89 以及非 root Deployment
364/364。该 r22 workspace Clippy 运行暴露了约 30 个历史结构 lint，而不是通过；修正已进入后续源码
快照，但 r29 macOS artifact workflow 没有运行 workspace Clippy，因此这里不把它冒充为 fresh
Clippy pass。

原生 Intel macOS r29 commit `944ce332`、run `31238285076` 已通过 locked Textual tests 和完整
governance checker，构建并验证公开 native CLI，组装可搬移 bundle，并真实走通 PTY 下的 typed
Inspection markers、Runtime ready、Textual→Runtime Echo、priority Ctrl-C、terminal restoration 和
父进程 joined shutdown；bundle checksum、executable mode、archive 和 artifact upload 也已通过。
真实 credentialed DeepSeek smoke 仍未完成，因此还不能把配置中的 DeepSeek 路径描述成外部验证
通过或 production ready。离线验证系统基座时，使用同一个配置 schema，将 `model.provider` 改为
`deterministic-echo-v1` 并省略 model/SecretRef；`echo: <你的消息>` 只证明 DeveloperLocal owner 链。
旧的独立 Rust reference frontend 现已删除；内部 Textual child 是唯一当前展示路径，也不存在第二个
公开 `paraegox chat` 入口。

当前 A2 仍是最小文本链：不流式、同时只允许一个 Model 调用、每轮只把当前输入发给模型；会话历史
回灌、Memory、Tools、规划和多 Agent 编排仍属于后续 Agent Core。父进程只把 owner-private bootstrap
文件路径交给内部 Textual child：一个用于 Agent 对话，存在时另一个用于只读本地 Inspection。Python
`AgentConversationClient` 只消费 Runtime Agent 路径，不打开 raw Zenoh，也看不到 provider/model 凭据。
另一个 strict typed client 会验证 owner-private PXIB v2 bootstrap，并在 Textual App 启动前只执行
一次无重试 PXIQ Latest 交换，严格关联 PXIP response 并解码完整 PXIS v2 snapshot。任何
bootstrap、transport、correlation 或 snapshot 错误都会阻止 UI 启动。成功时只显示三行只读
startup status；没有 watch、retry、cache、background refresh、action、持续监控、Ops 或
federated view。argv 不携带 raw identity、Node management capability、Zenoh route、capability token
或 Secret，parent 会从 child 环境同时移除 `OPENAI_API_KEY` 和 `DEEPSEEK_API_KEY`。这套
typed boundary 不是复活全能 ConsoleBridge。Node 合同、Unix 同一 registration tenure 的
NodeDaemon 持久状态和只读管理协议现在已经由 `paraegox-local` 真实消费，而不再只是独立机制。
launcher 会创建或安全重开精确的本地 Node tenure，提交一份初始 feature-only status，启动真实、
独立的 reference child，并只在本地 management channel、target、tenure 与 status fence 全部通过后
接受有界 PXNQ/PXNS Latest 响应。这个单目标初始 NodeStatus 的 Runtime observation 数量明确为零；
它**不证明** Runtime discovery、持续 observation/reconciliation、生产 Zenoh carrier、registration
acquisition、多主机运行或 distributed readiness。正常退出顺序为 Textual child/Agent IPC → Runtime
内部 Agent→Model→Fabric → NodeDaemon → Authority，并逐个 joined。

## 可运行的 G1 host-local Node 基座

下面这个独立公开命令只启动一个 split-trust Runtime 和一个 feature-only NodeDaemon child：

```text
paraegox node --config <absolute-node.toml>
```

它会绑定配置中的 restricted mTLS Runtime-apply listener，并让 listener 保持固定的 legacy generic
rejection；随后发布 RuntimeHost observation 为零的 Node status，通过一次 authenticated typed Latest
严格验证 child，最后输出精确 readiness marker：`paraegox: node ready`。它不启动 Authority、
DeploymentController、managed Fabric、Model、Agent、Inspection、Textual 或 chat 链，也不执行
Controller apply、registration、remote bootstrap 或 G2/多主机编排。

从 [`configs/paraegox-node.example.toml`](configs/paraegox-node.example.toml) 开始。把它复制到绝对普通
文件路径，将仅用于文档的 `192.0.2.10` listener 地址替换为宿主机真实拥有的 IPv4，并同步修改
`state_root` 和三条 credential path。启动前，同一个非 root 账号必须创建 canonical state root 及其
精确的 `credentials` 子目录，两者 mode 都是 `0700`。在该目录放入 PEM root CA、listener certificate
和 key；certificate SAN 必须包含配置 IP，key 必须是 `0600`，CA/certificate 不得允许 group/other
写入。示例只含非秘密 reference value 和 public verification key；只有 Controller/Authority enrollment
owner 才能替换这些 pin，绝不能填入 private seed。完整 credential 准备与启动命令见本地
`docs/runbooks/developer-local.md`。

Ubuntu r33 commit `7618f6a51c5eb5731874d2cdf3231603e3a824f7` 已通过 workspace format、locked
metadata、workspace all-target check 和 warnings-denied workspace all-target Clippy。完整
`paraegox-local` unit binary 以非 root 身份 98/98 通过；另有 9 个 focused Local filter 和 3 个非 root
Runtime split-trust/provisioning filter 通过。真实非 root process smoke 到达 readiness marker，且进程树
只有一个 child、一个非 loopback TLS listener 和两条预期 private Unix socket。SIGTERM 与 SIGINT 均
返回 0；restart 保持 PXNI/PXNB hash 逐字相同；强制杀死 child 后 parent 以 `PXLC-NODE-CHILD`
fail closed；root 启动在写 state 前以 `PXLC-EXECUTION-IDENTITY` 拒绝。这些事实只证明 G1 host-local
基座及其 cleanup/restart 边界。

在建的双目标 DeveloperLocal composition 仍是内部实现；当前没有公开的
`developer-distributed-fixture-v1` 命令，也不宣称分布式系统已经可运行。

Unix-only `paraegox-noded developer-local-reference-v1` 也能独立重开一份由外部授权的 exact tenure，
并通过 same-user、token-bound 本地 socket 返回最后一次已提交状态。新增的
`developer-local-runtime-observation-v1` 模式会在独立的 owner-private 本地 capability socket 上验证
Runtime 已签名的 PXQR/PXQS 交换，并在回应前原子发布对应的新 Node 状态。这是本地认证观测适配器，
其短时 query challenge 精确绑定 Node tenure、observation endpoint、Runtime authority、apply descriptor 和待发布序列。
认证后的绝对截止时间会同时进入状态摘要和持久状态，消费者必须与相对 freshness 一并校验；到期后
管理端不会再返回该观测产生的旧状态。多 Runtime 状态采用所保留 Runtime 中最早的截止时间，因此刷新
一个 Runtime 不会顺带给另一个续鲜；已提交的同一请求仍可恢复丢失的 ACK，且不会借此续鲜。
这不是生产 Zenoh 观测或 Runtime apply。注册获取、持续协调、双主机证据、federated Inspection/Ops
与 Web Console 仍在开发中。

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。
