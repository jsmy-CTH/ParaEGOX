//! Internal deployment-side producer for complete canonical Runtime apply-request drafts.

#[cfg(unix)]
#[expect(dead_code, reason = "Awaiting admitted executable consumer")] // GOV-WAIVER-0002
mod controller_initializer;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0002
mod controller_journal;
#[cfg(unix)]
#[expect(dead_code, reason = "Awaiting admitted executable consumer")] // GOV-WAIVER-0002
mod controller_store;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0002
mod deck;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0002
mod envelope;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0002
mod plan;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0002
mod planner;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0002
mod projection;
#[cfg(unix)]
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0002
mod tenure_authority;
mod tenure_authority_process;
#[cfg(unix)]
#[expect(dead_code, reason = "Awaiting admitted executable consumer")] // GOV-WAIVER-0002
mod tenure_client;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0002
mod tenure_protocol;

pub use tenure_authority_process::{TenureAuthorityProcessError, run_tenure_authority_process};
