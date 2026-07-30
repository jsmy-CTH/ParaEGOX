//! Runtime-owned admission seam for complete canonical apply requests.
//!
//! This layer validates the assignment body before delegating the unchanged
//! signed envelope to B2 authentication and temporal admission. It owns no
//! endpoint, journal, clock source, I/O, or RuntimeHost lifecycle.

use core::fmt;

use paraegox_runtime_contracts::assignment::{RequestWireError, RuntimePlanSlice};

use crate::admission::{AdmissionDisposition, AdmissionError, AdmissionState, AdmissionTransition};
use crate::apply_state::AdmittedApply;

/// Pure admission result retaining the exact authenticated Slice body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeRequestAdmissionTransition {
    admission: AdmissionTransition,
    slice: RuntimePlanSlice,
}

impl RuntimeRequestAdmissionTransition {
    pub(super) const fn new(admission: AdmissionTransition, slice: RuntimePlanSlice) -> Self {
        Self { admission, slice }
    }

    /// Returns the candidate replay/temporal snapshot.
    #[must_use]
    pub(crate) const fn next_state(&self) -> &AdmissionState {
        self.admission.next_state()
    }

    /// Returns the apply-control value admitted by the concrete verifier.
    #[must_use]
    pub(crate) const fn admitted(&self) -> &AdmittedApply {
        self.admission.admitted()
    }

    /// Returns the exact assignment body bound to the admitted commitment.
    #[must_use]
    pub(crate) const fn slice(&self) -> &RuntimePlanSlice {
        &self.slice
    }

    /// Reports whether the signed envelope was fresh or an exact replay.
    #[must_use]
    pub(crate) const fn disposition(&self) -> AdmissionDisposition {
        self.admission.disposition()
    }

    /// Consumes every value a future journal/assembly owner must keep together.
    #[must_use]
    pub(crate) fn into_parts(self) -> (AdmissionState, AdmittedApply, RuntimePlanSlice) {
        let (state, admitted) = self.admission.into_parts();
        (state, admitted, self.slice)
    }
}

/// Fail-closed complete-request decoding or authenticated admission errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeRequestAdmissionError {
    RequestWire(RequestWireError),
    Admission(AdmissionError),
}

impl From<RequestWireError> for RuntimeRequestAdmissionError {
    fn from(value: RequestWireError) -> Self {
        Self::RequestWire(value)
    }
}

impl From<AdmissionError> for RuntimeRequestAdmissionError {
    fn from(value: AdmissionError) -> Self {
        Self::Admission(value)
    }
}

impl fmt::Display for RuntimeRequestAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestWire(error) => {
                write!(formatter, "complete apply request rejected: {error}")
            }
            Self::Admission(error) => write!(formatter, "signed apply admission rejected: {error}"),
        }
    }
}

impl std::error::Error for RuntimeRequestAdmissionError {}
