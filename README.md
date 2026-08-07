# ParaEGOX

ParaEGOX is a distributed Agent OS for robotics and embodied agents, currently being rebuilt from the ground up.

ParaEGOX is based on [PhanthyMotus](https://github.com/4paradigm/phanthymotus). The original baseline remains available on the `archive/phanthymotus-baseline` branch, with its license attribution preserved.

> Status: the first DeveloperLocal system substrate now starts and supports TUI conversations. ParaEGOX is adopting a Rust-first core with polyglot managed workloads; no stable release is currently available.

## Runnable DeveloperLocal slice

The `paraegox` binary composes the real Authority, DeploymentController, Runtime, Runtime-managed
Zenoh Fabric, ModelService, AgentService, a separate NodeDaemon reference child, and a separate TUI
child. Runtime starts Fabric, then Model, then Agent, and exposes a conversation capability only
after the exact signed PXMT ActiveReady receipt is durably committed.

There is one public conversation command:

```text
paraegox chat --config <absolute-paraegox.toml>
```

Provider, model, state root, and Fabric listener are selected by the strict versioned TOML config,
not by provider-specific subcommands or override flags. Secret values never belong in config or
argv; config contains only an exact SecretRef. The repository keeps one credential-free example at
[`configs/paraegox.example.toml`](configs/paraegox.example.toml). It currently selects DeepSeek as a
replaceable validation backend, not as a CLI mode or default model.

On macOS, keep the example's state root under canonical `/private/tmp` because `/tmp` is a symlink
rejected by the path policy. To exercise the configured DeepSeek path, supply the referenced Secret
through the process environment and pass an absolute config path:

```zsh
read -s 'DEEPSEEK_API_KEY?DeepSeek API key: '; echo
export DEEPSEEK_API_KEY
CONFIG_PATH="$(pwd)/configs/paraegox.example.toml"
CARGO_BUILD_JOBS=1 cargo run --locked -p paraegox-local -- \
  chat --config "$CONFIG_PATH"
unset DEEPSEEK_API_KEY
```

Remote validation of source snapshot r18 has passed `cargo fmt --all --check`, warning-free
workspace all-targets compilation, all 19 `paraegox-model-adapters` tests, and all 87
DeveloperLocal tests under a non-root identity. Ruff and the governance checker also passed; 391
governance, contract, and Agent-worker tests passed on the Mac without invoking Rust. These results
are not the full workspace test/clippy/doc gates, fresh Ubuntu CI, or production evidence. A
credentialed external DeepSeek smoke and a Mac-built executable are still pending, so the configured
DeepSeek path must not yet be described as externally validated or production ready. For an offline
substrate check, use the same config schema with
`model.provider = "deterministic-echo-v1"` and omit model/SecretRef; `echo: <message>` proves only the
DeveloperLocal owner chain. The standalone `paraegox-tui fixture-v1` test executable remains a
labelled fixture and is not an alternative public `paraegox chat` entry.

The current A2 slice is non-streaming, permits one Model call in flight, and sends only the current
turn's prompt; conversation-history recall, Memory, Tools, planning, and multi-agent orchestration
remain later Agent Core work. The parent supplies the TUI child only two owner-private bootstrap-file
paths: one for Agent conversation and one for read-only local Inspection. Explicit Inspection v2
preserves the byte-exact five-owner v1 snapshot and adds one public-safe NodeDaemon startup record to
the Status view. The child removes both `OPENAI_API_KEY` and `DEEPSEEK_API_KEY` from its environment
and receives no raw identity, Node management capability, Zenoh route, capability token, or Secret
through argv. This is a local authenticated read path, not federated Inspection/Ops.

The Node contract, Unix same-tenure durable NodeDaemon state, and read-only management protocol are
now consumed by `paraegox-local`, rather than existing only as a standalone mechanism. The launcher
creates or securely reopens the exact local Node tenure, commits an initial feature-only status,
starts a real separate reference child, and accepts its bounded PXNQ/PXNS Latest response only after
the local management channel, target, tenure, and status fences authenticate. That initial
single-target NodeStatus deliberately contains zero Runtime observations. It therefore does **not**
prove Runtime discovery, continuous observation or reconciliation, a production Zenoh carrier,
registration acquisition, multi-host operation, or distributed readiness. Normal exit joins the
TUI/IPC boundary first, then Runtime-managed Agent→Model→Fabric shutdown, the NodeDaemon, and finally
Authority.

The in-progress two-target DeveloperLocal composition remains internal. There is no public
`developer-distributed-fixture-v1` command and no runnable distributed-system claim yet.

A Unix-only `paraegox-noded developer-local-reference-v1` process can also reopen one externally
authorized exact tenure and serve its last committed status through a same-user, token-bound local socket.
An additive `developer-local-runtime-observation-v1` mode verifies an existing Runtime-signed PXQR/PXQS
exchange on a separate owner-private local capability socket and atomically publishes the resulting fresh
Node status before acknowledging it. Its short-lived query challenge is bound to the exact Node tenure,
observation endpoint, Runtime authority, apply descriptor, and proposed status sequence. The authenticated
absolute expiry is carried in the status digest and durable state: consumers enforce it in addition to the
relative budget, and after it the management endpoint will not re-serve that observation-backed status. A
multi-Runtime publication uses the earliest retained deadline, so observing one Runtime cannot renew another;
an exact committed request can still recover a lost acknowledgement without renewing freshness. This is a
local authenticated observation adapter, not production Zenoh observation or Runtime apply. Registration
acquisition, continuous reconciliation, two-host proof, federated Inspection/Ops, and the Web Console
remain in progress.

## License

Licensed under the [Apache License 2.0](LICENSE).
