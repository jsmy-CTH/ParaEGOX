# ParaEGOX

ParaEGOX is a distributed Agent OS for robotics and embodied agents, currently being rebuilt from the ground up.

ParaEGOX is based on [PhanthyMotus](https://github.com/4paradigm/phanthymotus). The original baseline remains available on the `archive/phanthymotus-baseline` branch, with its license attribution preserved.

> Status: the current worktree contains the first DeveloperLocal backend, Textual chat composition,
> and typed one-shot Inspection startup view. The r21 integration run reached a real Echo terminal,
> but its joined exit exceeded the workflow's 20-second limit, so presentation closeout remains
> pending an r22 rerun with a 60-second exit budget. ParaEGOX is adopting a Rust-first core with
> polyglot managed workloads; no stable release is currently available.

## Runnable DeveloperLocal slice

The `paraegox` binary composes the real Authority, DeploymentController, Runtime, Runtime-managed
Zenoh Fabric, ModelService, AgentService, a separate NodeDaemon reference child, owner-private Agent
and Inspection IPC, and an internal Python Textual child. Runtime starts Fabric, then Model, then
Agent, and exposes a conversation capability only after the exact signed PXMT ActiveReady receipt is
durably committed.

There is one public conversation command:

```text
paraegox chat --config <absolute-paraegox.toml>
```

Provider, model, state root, and Fabric listener are selected by the strict versioned TOML config,
not by provider-specific subcommands or override flags. Secret values never belong in config or
argv; config contains only an exact SecretRef. The repository keeps one credential-free example at
[`configs/paraegox.example.toml`](configs/paraegox.example.toml). It currently selects DeepSeek as a
replaceable validation backend, not as a CLI mode or default model.

The Textual child is installed from this repository's Python project. In a development checkout,
prepare and activate the locked environment before starting `paraegox`; the Rust parent deliberately
has no hidden Ratatui or transport fallback if the internal `paraegox-console` executable is absent:

```zsh
uv sync --locked
source .venv/bin/activate
command -v paraegox-console
```

`paraegox-console` is internal packaging, not a second public conversation command. On macOS, keep
the example's state root under canonical `/private/tmp` because `/tmp` is a symlink rejected by the
path policy. The macOS CI artifact is a relocatable directory containing `paraegox`, its executable
`paraegox-console` sibling, and vendored packages under `python/`; keep them together and provide
Python 3.11 or newer as `python3` on `PATH`. To exercise the configured DeepSeek path, supply the
referenced Secret through the process environment and pass an absolute config path:

```zsh
read -s 'DEEPSEEK_API_KEY?DeepSeek API key: '; echo
export DEEPSEEK_API_KEY
CONFIG_PATH="$(pwd)/configs/paraegox.example.toml"
PARAEGOX_BIN=/absolute/path/to/native/paraegox
test -x "$PARAEGOX_BIN"
"$PARAEGOX_BIN" chat --config "$CONFIG_PATH"
unset DEEPSEEK_API_KEY
```

Build the native binary on the designated server or GitHub CI and download the complete bundle to
the Mac. Do not run Cargo on the Mac for this workflow.

Source snapshot r21 passed the build server's locked workspace check, all 36 Inspection tests, all
89 DeveloperLocal tests under a non-root identity, and all 364 Deployment tests under a non-root
identity. Its native Intel macOS CI run built the binary, passed the Python checks, and completed a
real Textual-to-Runtime Echo terminal. The workflow still failed because joined process exit exceeded
its 20-second limit. Formatting findings and four Clippy findings from the r21 gates have been fixed
in the Mac source authority, but those fixes are not claimed as passed until r22 reruns the remote
format/Clippy gates and the same macOS smoke with a 60-second exit budget. A credentialed external
DeepSeek smoke is also still pending, so the configured DeepSeek path must not yet be described as
externally validated or production ready. For an offline substrate check, use the same config schema with
`model.provider = "deterministic-echo-v1"` and omit model/SecretRef; `echo: <message>` proves only the
DeveloperLocal owner chain. The standalone Rust `paraegox-tui fixture-v1` executable is retained
temporarily as a retirement reference only: `paraegox-local` no longer depends on or launches it,
and it is not an alternative public `paraegox chat` entry. It is scheduled for deletion only after
the next replacement-validation gate passes; it is not claimed deleted today.

The current A2 slice is non-streaming, permits one Model call in flight, and sends only the current
turn's prompt; conversation-history recall, Memory, Tools, planning, and multi-agent orchestration
remain later Agent Core work. The parent supplies the internal Textual child only owner-private
bootstrap-file paths: one for Agent conversation and, when available, one for read-only local
Inspection. The Python `AgentConversationClient` consumes only the Runtime Agent path and never opens
raw Zenoh or sees provider/model credentials. A separate strict typed client validates the owner-private
PXIB v2 bootstrap and performs exactly one no-retry PXIQ Latest exchange before the Textual App starts;
it strictly correlates the PXIP response and decodes the complete PXIS v2 snapshot. Any bootstrap,
transport, correlation, or snapshot failure prevents the UI from starting. A successful read is shown
as three read-only startup-status lines; there is no watch, retry, cache, background refresh, action,
continuous monitoring, Ops, or federated view. The parent removes both `OPENAI_API_KEY` and
`DEEPSEEK_API_KEY` from the child environment, and argv carries no raw identity, Node management
capability, Zenoh route, capability token, or Secret. This typed boundary is not a revived all-in-one
ConsoleBridge.

The Node contract, Unix same-tenure durable NodeDaemon state, and read-only management protocol are
now consumed by `paraegox-local`, rather than existing only as a standalone mechanism. The launcher
creates or securely reopens the exact local Node tenure, commits an initial feature-only status,
starts a real separate reference child, and accepts its bounded PXNQ/PXNS Latest response only after
the local management channel, target, tenure, and status fences authenticate. That initial
single-target NodeStatus deliberately contains zero Runtime observations. It therefore does **not**
prove Runtime discovery, continuous observation or reconciliation, a production Zenoh carrier,
registration acquisition, multi-host operation, or distributed readiness. Normal exit joins the
Textual child and Agent IPC boundary first, then Runtime-managed Agent→Model→Fabric shutdown, the
NodeDaemon, and finally Authority.

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
