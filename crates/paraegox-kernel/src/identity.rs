//! Identity values that are genuinely shared across mechanism owners.

/// Identifies one RuntimeHost target without assigning deployment ownership.
///
/// Identity owners are intentionally not interchangeable:
///
/// ```compile_fail
/// use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
///
/// fn select_target(_target: RuntimeHostId) {}
///
/// let principal = PrincipalRef::from_bytes([7; 16]);
/// select_target(principal);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeHostId([u8; 16]);

impl RuntimeHostId {
    /// Creates an opaque identity from its canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Identifies the authenticated principal admitted by an owning verifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrincipalRef([u8; 16]);

impl PrincipalRef {
    /// Creates an opaque principal reference from its canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical principal bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{PrincipalRef, RuntimeHostId};

    #[test]
    fn identity_types_do_not_compare_across_owners() {
        let bytes = [7; 16];
        let host = RuntimeHostId::from_bytes(bytes);
        let principal = PrincipalRef::from_bytes(bytes);

        assert_eq!(host.as_bytes(), principal.as_bytes());
    }
}
