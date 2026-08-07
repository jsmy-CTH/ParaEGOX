# ParaEGOX

ParaEGOX 是一个面向机器人与具身智能体的分布式 Agent OS，目前正在从零重构。

ParaEGOX 基于 [PhanthyMotus](https://github.com/4paradigm/phanthymotus) 构建。原始基线保留在 `archive/phanthymotus-baseline` 分支，并保留其许可证归属。

> 当前状态：首个 DeveloperLocal 系统基座已经可以启动并在 TUI 对话；生产核心机制优先采用 Rust，Python/C++ 作为受管工作负载与生态语言，暂未提供稳定版本。

## 当前可运行切片

`paraegox` binary 会沿真实 owner 链启动 Authority、DeploymentController、Runtime，以及由 Runtime
管理的 Zenoh Fabric、ModelService、AgentService；同时启动一个独立 NodeDaemon reference child 和
一个独立 TUI child。Runtime 按 Fabric → Model → Agent 启动，只有精确、已签名的 PXMT ActiveReady
回执持久提交后才向 TUI 发放对话能力。

公开对话入口只有一个：

```text
paraegox chat --config <absolute-paraegox.toml>
```

provider、model、state root 和 Fabric listener 由 strict versioned TOML 配置选择，不是 provider 专属
子命令或 override flags。Secret value 不得进入配置或 argv，配置只保存精确 SecretRef。仓库唯一的
无凭据示例是 [`configs/paraegox.example.toml`](configs/paraegox.example.toml)；它当前选择 DeepSeek
作为可替换验证后端，不表示 CLI mode 或默认模型。

macOS 请保留示例中的 canonical `/private/tmp` state root（`/tmp` 是 symlink，会被安全校验拒绝）。
验证配置中的 DeepSeek 路径时，通过进程环境提供它引用的 Secret，并传入配置的绝对路径：

```zsh
read -s 'DEEPSEEK_API_KEY?DeepSeek API key: '; echo
export DEEPSEEK_API_KEY
CONFIG_PATH="$(pwd)/configs/paraegox.example.toml"
CARGO_BUILD_JOBS=1 cargo run --locked -p paraegox-local -- \
  chat --config "$CONFIG_PATH"
unset DEEPSEEK_API_KEY
```

远端 source snapshot r18 已通过 `cargo fmt --all --check`、无 warning 的 workspace all-targets
编译、`paraegox-model-adapters` 19/19 测试，以及非 root 身份下的 DeveloperLocal 87/87 测试；Ruff 与
governance checker 通过，Mac 上不调用 Rust 的 governance、contract 和 Agent-worker 测试为 391/391。
r19 随后由原生 Intel Mac CI 构建并校验 x86_64 executable；下载后的同一 binary 已在 Mac 完成一次
真实离线 Echo TUI 往返并正常退出。这些结果不等于完整 workspace test/clippy/doc gates、fresh Ubuntu CI
或 production evidence。真实 credentialed DeepSeek smoke 仍未完成，因此还不能把配置中的 DeepSeek
路径描述成外部验证通过或 production ready。离线验证系统基座时，使用同一个配置 schema，将 `model.provider` 改为
`deterministic-echo-v1` 并省略 model/SecretRef；`echo: <你的消息>` 只证明 DeveloperLocal owner 链。
独立的 `paraegox-tui fixture-v1` test executable 仍是明确标记的 fixture，不是第二个公开
`paraegox chat` 入口。

当前 A2 仍是最小文本链：不流式、同时只允许一个 Model 调用、每轮只把当前输入发给模型；会话历史
回灌、Memory、Tools、规划和多 Agent 编排仍属于后续 Agent Core。父进程只把 Agent 对话和只读本地
Inspection 两个 owner-private bootstrap 文件路径交给 TUI child。argv 不携带 raw identity、Node
management capability、Zenoh route、capability token 或 Secret，child 环境会同时移除
`OPENAI_API_KEY` 和 `DEEPSEEK_API_KEY`。这只是本机 authenticated read path，不等于 federated
Inspection/Ops。Node 合同、Unix 同一 registration tenure 的
NodeDaemon 持久状态和只读管理协议现在已经由 `paraegox-local` 真实消费，而不再只是独立机制。
launcher 会创建或安全重开精确的本地 Node tenure，提交一份初始 feature-only status，启动真实、
独立的 reference child，并只在本地 management channel、target、tenure 与 status fence 全部通过后
接受有界 PXNQ/PXNS Latest 响应。这个单目标初始 NodeStatus 的 Runtime observation 数量明确为零；
它**不证明** Runtime discovery、持续 observation/reconciliation、生产 Zenoh carrier、registration
acquisition、多主机运行或 distributed readiness。正常退出顺序为 TUI/IPC → Runtime 内部
Agent→Model→Fabric → NodeDaemon → Authority，并逐个 joined。

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
