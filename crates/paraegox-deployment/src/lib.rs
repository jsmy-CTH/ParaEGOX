//! Internal deployment-side producer for complete canonical Runtime apply-request drafts.

#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod controller_apply;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod controller_bootstrap;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod controller_initializer;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod controller_journal;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod controller_query;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod controller_reconcile;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod controller_store;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod controller_tenure;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod deck;
mod deployment_process;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod envelope;
mod manifest_ingress;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod plan;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod planner;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod projection;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod runtime_control_client;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod tenure_authority;
mod tenure_authority_process;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod tenure_client;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod tenure_protocol;

pub use deployment_process::{DeploymentdProcessError, run_deploymentd_process};
pub use tenure_authority_process::{TenureAuthorityProcessError, run_tenure_authority_process};
