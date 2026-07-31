//! External RuntimeHost process supervision reference profile.
//!
//! The library is intentionally separate from the RuntimeHost reactor. Its
//! service-manager adapter owns the child process and restart/quarantine
//! ledger; it does not model a P5 NodeDaemon, Node facts, Deployment desired
//! state, or Runtime/ProcessDomain recovery receipts.

#[cfg(unix)]
pub mod service_manager;
