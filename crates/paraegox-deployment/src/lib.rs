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
#[cfg(unix)]
mod developer_fixture_agent_stack;
#[cfg(unix)]
mod developer_local_tenure_authority;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod distributed_agent_stack_apply;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod distributed_agent_stack_node_reconcile;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod distributed_agent_stack_producer;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod distributed_agent_stack_store;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod managed_agent_stack_apply;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod managed_agent_stack_producer;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod managed_fabric_apply;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod managed_fabric_producer;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod managed_fabric_store;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod managed_model_agent_stack_apply;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod managed_model_agent_stack_producer;
#[cfg(unix)]
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod managed_serving_client;
mod manifest_ingress;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod plan;
#[expect(dead_code, reason = "Staged private members await wider use")] // GOV-WAIVER-0002
mod planner;
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
#[cfg(unix)]
pub use developer_fixture_agent_stack::{
    DeveloperFixtureAgentStackDeactivationOutcomeV1, DeveloperFixtureAgentStackError,
    DeveloperFixtureAgentStackInputV1, DeveloperFixtureAgentStackOutcomeV1,
    DeveloperFixtureControllerCredentialsV1, DeveloperFixtureDerivedIdentityV1,
    DeveloperFixtureDistributedAgentStackError, DeveloperFixtureDistributedAgentStackInputV1,
    DeveloperFixtureDistributedAgentStackOutcomeV1, DeveloperFixtureDistributedCoordinatorV1,
    DeveloperFixtureDistributedNodeV1, DeveloperFixtureDistributedTargetV1,
    DeveloperFixtureDistributedTransportV1, DeveloperFixtureFabricEndpointV1,
    DeveloperFixtureIdentitySeedV1, DeveloperFixtureModelAgentStackDeactivationOutcomeV1,
    DeveloperFixtureModelAgentStackError, DeveloperFixtureModelAgentStackInputV1,
    DeveloperFixtureModelAgentStackOutcomeV1, DeveloperFixturePathsV1,
    DeveloperFixtureRuntimePinsV1, DeveloperProvisionedAgentStackInputV1,
    DeveloperProvisionedAgentStackOutcomeV1, DeveloperProvisionedModelAgentStackInputV1,
    DeveloperProvisionedModelAgentStackOutcomeV1, PreparedDeveloperFixtureDistributedAgentStackV1,
    complete_developer_fixture_distributed_agent_stack_v1,
    deactivate_developer_fixture_agent_stack_v1, deactivate_developer_fixture_model_agent_stack_v1,
    deactivate_developer_provisioned_model_agent_stack_v1,
    prepare_developer_fixture_distributed_agent_stack_v1, run_developer_fixture_agent_stack_v1,
    run_developer_fixture_model_agent_stack_v1, run_developer_provisioned_agent_stack_v1,
    run_developer_provisioned_model_agent_stack_v1,
};
#[cfg(unix)]
pub use developer_local_tenure_authority::{
    DeveloperLocalPeerIdentityV1, DeveloperLocalTenureAuthorityConfigV1,
    DeveloperLocalTenureAuthorityError, DeveloperLocalTenureAuthorityFactsV1,
    DeveloperLocalTenureAuthorityIdentityBytesV1, DeveloperLocalTenureAuthorityV1,
};
pub use tenure_authority_process::{TenureAuthorityProcessError, run_tenure_authority_process};
