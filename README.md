# ParaEGOX

ParaEGOX is a distributed Agent OS for robotics and embodied agents, currently being rebuilt from the ground up.

ParaEGOX is based on [PhanthyMotus](https://github.com/4paradigm/phanthymotus). The original baseline remains available on the `archive/phanthymotus-baseline` branch, with its license attribution preserved.

> Status: the current worktree contains the first DeveloperLocal backend, Textual chat composition,
> and typed one-shot Inspection startup view. Native Intel macOS r29 artifact run `31238285076`
> passed the real relocated-bundle path through Inspection, Runtime Agent IPC, Echo, Textual Ctrl-C,
> terminal restoration, and joined parent shutdown. Textual is now the sole DeveloperLocal
> presentation path; the retired Rust reference frontend has been removed. Ubuntu r33 commit
> `7618f6a51c5eb5731874d2cdf3231603e3a824f7` additionally validates the public G1 host-local
> `paraegox node` substrate. The current source additively wires the G2 host-side node profile and
> the public `paraegox deployment` Controller composition described below. Ubuntu r73 exact ref
> `96bbb26f1d8013d2a3ca4020e88b0faf3135fbff` is the latest validated code ref for that composition;
> its real cross-host process smoke is still pending. ParaEGOX is adopting a Rust-first core with
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
argv; config contains only an exact SecretRef. The chat configuration has one credential-free example at
[`configs/paraegox.example.toml`](configs/paraegox.example.toml). It currently selects DeepSeek as a
replaceable validation backend, not as a CLI mode or default model.

The Textual child is installed from this repository's Python project. In a development checkout,
prepare and activate the locked environment before starting `paraegox`; the Rust parent deliberately
has no alternate frontend or transport fallback if the internal `paraegox-console` executable is
absent:

```zsh
uv sync --locked
source .venv/bin/activate
command -v paraegox-console
```

`paraegox-console` is internal packaging, not a second public conversation command. On macOS, keep
the example's state root under canonical `/private/tmp` because `/tmp` is a symlink rejected by the
path policy. The macOS CI artifact contains a SHA-256-checked `tar.gz`; verify its adjacent
`.sha256` file before extraction. The extracted relocatable directory contains `paraegox`, its
executable `paraegox-console` sibling, and vendored packages under `python/`; keep them together and
provide Python 3.11 or newer as `python3` on `PATH`. To exercise the configured DeepSeek path,
supply the referenced Secret through the process environment and pass an absolute config path:

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

Historical Ubuntu validation of r22 source snapshot `ff2d8109` passed workspace formatting, locked
metadata, and locked all-targets check. It also passed all 39 Inspection tests, all 89
DeveloperLocal tests under a non-root identity, and all 364 Deployment tests under a non-root
identity. That r22 workspace Clippy run exposed approximately 30 historical structural lints rather
than passing. Their corrections are present in later source snapshots, but the r29 macOS artifact
workflow did not run workspace Clippy and is not presented as a fresh Clippy pass.

Native Intel macOS r29 commit `944ce332` run `31238285076` passed the locked Textual tests and full
governance checker, built and verified the public native CLI, staged the relocatable bundle, and ran
the real PTY path through typed Inspection markers, Runtime readiness, Textual-to-Runtime Echo,
priority Ctrl-C, terminal restoration, and joined parent shutdown. It also verified the bundle
checksums, executable modes, archive, and artifact upload. A credentialed external DeepSeek smoke is
still pending, so the configured DeepSeek path must not yet be described as externally validated or
production ready. For an offline substrate check, use the same config schema with
`model.provider = "deterministic-echo-v1"` and omit model/SecretRef; `echo: <message>` proves only the
DeveloperLocal owner chain. The earlier standalone Rust reference frontend has now been removed;
the internal Textual child is the only current presentation path and there is no alternate public
`paraegox chat` entry.

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

## Runnable Node host substrate: G1 schema v1 and G2 host-side schema v2

The separate public command below always starts one split-trust Runtime and one NodeDaemon child.
Its strict config schema selects the host profile; there is no second G2 command:

```text
paraegox node --config <absolute-node.toml>
```

With `schema_version = 1`, the command retains the validated G1 path: it binds the restricted mTLS
Runtime-apply listener on its fixed legacy generic-rejection behavior, publishes a feature-only Node
status with zero RuntimeHost observations, and verifies the child through one authenticated typed
Latest exchange.

With `schema_version = 2`, the same command additively starts the G2 **host-side** path. The Runtime
listener accepts the bounded Controller-signed PXCC control carrier and returns Runtime-signed PXDR
Describe facts; while LegacyReady it also carries the frozen PXQR query and accepts the authenticated
PXFB one-way cutover. A separate Node listener authenticates the Controller before dispatching
Describe, Latest, Watch, observation-challenge, or Runtime-observation publication through the
existing sole-owner NodeDaemon store and observation capability. Runtime readiness facts are
cross-checked before the observation bridge is created. Schema v2 therefore provides the real
Ubuntu-side listeners, durable owners, and bridge needed by a later external Controller; it does not
embed that Controller in the node process.

Both schemas print `paraegox: node ready` only after their configured local owners and listeners have
started. The marker does not prove that a Controller connected, PXFB cutover completed, a Runtime
observation was published, or a desired Agent stack was applied. Neither schema starts Authority,
DeploymentController, managed Fabric, Model, Agent, Inspection, Textual, or the chat chain. The
separate public Controller command described below now exists, but there is still no end-to-end
two-host process proof, remote Agent conversation path, remote TUI, or partition/reconnect policy.

Start from [`configs/paraegox-node.example.toml`](configs/paraegox-node.example.toml). Copy it to an
absolute regular-file path, replace both documentation-only `192.0.2.10` listener addresses with
IPv4 addresses actually assigned to the host, and update `state_root` plus all six credential paths
together. Before launch, the same non-root account must create the canonical state root and its exact
`credentials` child at mode `0700`. Provision distinct PEM CA/certificate/key files for the Runtime
and Node listeners in that one directory; both certificate SANs must contain their configured IP,
both keys must be mode `0600`, and CA/certificate files must not be group- or other-writable. The
example selects schema v2. To retain G1, set `schema_version = 1`, remove the complete
`[node_control]` table, and provision only the three Runtime-listener files. The example contains only
non-secret reference values and public verification keys; replace those pins only from the owning
Controller/Authority enrollment workflow, never with private seeds. Full credential preparation and
launch commands are in the local `docs/runbooks/developer-local.md` runbook.

Ubuntu r33 commit `7618f6a51c5eb5731874d2cdf3231603e3a824f7` passed workspace formatting,
locked metadata, workspace all-target checking, and workspace all-target Clippy with warnings denied.
The complete `paraegox-local` unit binary passed 98/98 tests as a non-root user; nine focused Local
filters and three focused non-root Runtime split-trust/provisioning filters also passed. A real
non-root process smoke reached the readiness marker with exactly one child, one non-loopback TLS
listener and the two expected private Unix sockets. SIGTERM and SIGINT each exited zero, restart
preserved byte-identical PXNI/PXNB hashes, forced child death made the parent fail closed with
`PXLC-NODE-CHILD`, and root launch failed before state with `PXLC-EXECUTION-IDENTITY`. These facts
prove the G1 host-local substrate and cleanup/restart boundary only.

The host-side G2 validation ref is r51 `b1d1206d2187b85d335ae352c226274d8e9d5827`. Ubuntu passed workspace
format checking, the focused public-help test 1/1, the complete governance checker, workspace
all-target checking, workspace all-target Clippy with warnings denied, and the complete non-root
`paraegox-local` suite 111/111. All workspace all-target test executables also compiled and linked
successfully under `--no-run`. Workspace doc tests passed, including two Fabric, one Kernel, and one
runtime-contracts compile-fail doctest; other crates had no doctests. `--no-run` is not a claim that
the complete workspace test suite executed.

Separately, after the PXQR authentication nonce was bound to the exact Node observation challenge,
the corresponding Deployment source/binary lineage passed the complete non-root Deployment suite
374/374. No later change through r51 modified Deployment source, but the handoff did not preserve the
exact immutable ref of that 374/374 invocation. It is therefore lineage evidence, not a claim that
r51 itself reran the Deployment suite.

The real non-root r48 schema-v2 process smoke reached Ready with exactly one hidden Node child, two
non-loopback TLS listeners (`172.17.0.2:28448` and `:28449`), and the expected Runtime, management,
and observation Unix sockets. A provisioned Controller client certificate completed a TLS handshake
with each listener; both rejected a client without a certificate. SIGTERM exited zero and cleaned
up; a same-state restart reached Ready and exited zero with stable PXNI/PXNB/PXND digests. Killing the
Node child made the parent exit one with `PXLC-NODE-CHILD` and removed listeners, PXOB, and processes;
the same state then restarted successfully and SIGINT exited zero. Root launch failed before state
mutation with `PXLC-EXECUTION-IDENTITY`. This proves the r48 host process and mTLS/lifecycle boundary,
not a PXCC/PXNR semantic exchange or cutover. The later public Controller composition does not
retroactively turn this host-only smoke into a two-host control-sequence, remote Agent conversation,
remote TUI, or reconnect result. The older two-target DeveloperLocal fixture remains internal; there
is no public `developer-distributed-fixture-v1` command and no runnable full distributed-system claim
yet.

## Public Developer DeploymentController composition

The third public command starts one bounded Controller-side owner graph:

```text
paraegox deployment --config <absolute-paraegox-deployment.toml>
```

Its strict TOML schema v1 contains only local filesystem authorities: `state_root`, an exact PXEA
`enrollment_artifact_file` plus its lowercase whole-file `enrollment_artifact_sha256`, separate
Controller and tenure-Authority signing-seed files, the Authority state directory/socket, and
`[runtime_connector]` / `[node_connector]` CA, client-certificate, and client-private-key paths.
Unknown fields and alternate CLI submodes fail closed. Endpoint, route, target, principal, trust,
manifest, and credential-reference semantics are accepted only from the independently pinned PXEA;
they cannot be restated in TOML as a second configuration authority. Start from
[`configs/paraegox-deployment.example.toml`](configs/paraegox-deployment.example.toml).

The schema-v2 Node process publishes canonical `<node-state-root>/node/enrollment-v1.pxea` only after
its Runtime and Node bootstraps have been proved. PXEA v1 is public-safe and Runtime-attested: it
contains the immutable Runtime manifest and the complete public Runtime/Node transport, identity,
and enrollment pins, but no bearer token, signing seed, private-key bytes, or private-key path. The
Controller side checks an independently transported whole-file SHA-256 before decoding any frame
length, signature, or semantic field, and then cross-checks its separately provisioned Controller
and Authority keys. The artifact signature is continuity evidence, not first-use trust.

`paraegox: deployment ready` has a deliberately narrow meaning. Local can print and flush it only
from the facade's `Ready` outcome, after the remote connector/cutover state is durable, the exact
PXFR managed-serving terminal is durably `ResponseDurable`, and a fresh post-PXFR PXDR Describe has
been verified as `ManagedReady` and durably committed. Delivery uncertainty, a publish state that
needs operator reconciliation, an invalid response, or a ManagedReady Describe without durable PXFR
cannot synthesize readiness; the command joins its owners and exits nonzero with a stable Deployment
error instead. The process performs one bounded non-retrying attempt and is not a continuous
reconciler.

Ubuntu validated exact r73 ref `96bbb26f1d8013d2a3ca4020e88b0faf3135fbff` with workspace
`cargo fmt --all --check`, locked workspace all-target checking, and warnings-denied locked workspace
all-target Clippy. The complete prebuilt `paraegox-local` test binary passed 129/129 and the complete
prebuilt `paraegox-deployment` test binary passed 387/387 as `nobody`, with
`RUST_MIN_STACK=16777216` and `--test-threads=1`. This is compile, lint, and unit evidence. A real
Mac-to-Ubuntu public-process smoke—including PXEA transfer/pinning, full semantic exchange, Ready,
signals, Authority-owner failure, and restart seams—has not yet run, so r73 is not presented as two-machine
execution evidence. It also supplies no target-scoped remote Agent descriptor, remote conversation,
remote TUI, or reconnect policy.

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
