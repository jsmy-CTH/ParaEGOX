//! Nonblocking items/bytes admission for pre-validation Zenoh frames.

use core::{fmt, num::NonZeroUsize, time::Duration};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

use crate::contract::MAX_ENVELOPE_BODY_BYTES;

pub(crate) const MAX_INGRESS_ITEMS: usize = 4_096;
pub(crate) const MAX_INGRESS_BYTES: usize = MAX_ENVELOPE_BODY_BYTES;
pub(crate) const MAX_INGRESS_FRAME_BYTES: usize = MAX_ENVELOPE_BODY_BYTES + 104;
pub(crate) const MAX_INGRESS_RESPONSE_BODY_BYTES: usize = MAX_ENVELOPE_BODY_BYTES;

/// Fixed admission and handler bounds for one request/response binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressLimits {
    max_items: NonZeroUsize,
    max_bytes: NonZeroUsize,
    max_frame_bytes: NonZeroUsize,
    max_response_body_bytes: usize,
    handler_timeout: Duration,
}

impl IngressLimits {
    /// Creates one immutable limit set.
    pub fn try_new(
        max_items: usize,
        max_bytes: usize,
        max_frame_bytes: usize,
        max_response_body_bytes: usize,
        handler_timeout: Duration,
    ) -> Result<Self, IngressLimitError> {
        let max_items = NonZeroUsize::new(max_items).ok_or(IngressLimitError::ZeroItems)?;
        let max_bytes = NonZeroUsize::new(max_bytes).ok_or(IngressLimitError::ZeroBytes)?;
        let max_frame_bytes =
            NonZeroUsize::new(max_frame_bytes).ok_or(IngressLimitError::ZeroFrameBytes)?;
        if max_items.get() > MAX_INGRESS_ITEMS {
            return Err(IngressLimitError::ItemsExceedProtocolBound);
        }
        if max_bytes.get() > MAX_INGRESS_BYTES {
            return Err(IngressLimitError::BytesExceedProtocolBound);
        }
        if max_frame_bytes.get() > max_bytes.get() {
            return Err(IngressLimitError::FrameExceedsTotalBytes);
        }
        if max_frame_bytes.get() > MAX_INGRESS_FRAME_BYTES {
            return Err(IngressLimitError::FrameExceedsProtocolBound);
        }
        if max_response_body_bytes > MAX_INGRESS_RESPONSE_BODY_BYTES {
            return Err(IngressLimitError::ResponseExceedsProtocolBound);
        }
        if handler_timeout.is_zero() {
            return Err(IngressLimitError::ZeroHandlerTimeout);
        }
        Ok(Self {
            max_items,
            max_bytes,
            max_frame_bytes,
            max_response_body_bytes,
            handler_timeout,
        })
    }

    #[must_use]
    pub const fn max_items(self) -> usize {
        self.max_items.get()
    }

    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes.get()
    }

    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes.get()
    }

    #[must_use]
    pub const fn max_response_body_bytes(self) -> usize {
        self.max_response_body_bytes
    }

    #[must_use]
    pub const fn handler_timeout(self) -> Duration {
        self.handler_timeout
    }
}

/// Invalid ingress limit relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressLimitError {
    ZeroItems,
    ZeroBytes,
    ZeroFrameBytes,
    ItemsExceedProtocolBound,
    BytesExceedProtocolBound,
    FrameExceedsTotalBytes,
    FrameExceedsProtocolBound,
    ResponseExceedsProtocolBound,
    ZeroHandlerTimeout,
}

impl fmt::Display for IngressLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroItems => "ingress item capacity must be nonzero",
            Self::ZeroBytes => "ingress byte capacity must be nonzero",
            Self::ZeroFrameBytes => "maximum frame size must be nonzero",
            Self::ItemsExceedProtocolBound => "ingress item capacity exceeds the protocol bound",
            Self::BytesExceedProtocolBound => "ingress byte capacity exceeds the protocol bound",
            Self::FrameExceedsTotalBytes => "one frame cannot exceed total ingress bytes",
            Self::FrameExceedsProtocolBound => "frame limit exceeds the envelope protocol bound",
            Self::ResponseExceedsProtocolBound => {
                "response body limit exceeds the envelope protocol bound"
            }
            Self::ZeroHandlerTimeout => "handler timeout must be nonzero",
        })
    }
}

impl std::error::Error for IngressLimitError {}

/// Read-only bounded-ingress facts. Values are observational, not desired truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FabricIngressSnapshot {
    queued_items: usize,
    queued_bytes: usize,
    admitted_frames: u64,
    rejected_oversize: u64,
    rejected_items_full: u64,
    rejected_bytes_full: u64,
    rejected_malformed: u64,
    rejected_stale: u64,
    rejected_closed: u64,
}

impl FabricIngressSnapshot {
    #[must_use]
    pub const fn queued_items(self) -> usize {
        self.queued_items
    }

    #[must_use]
    pub const fn queued_bytes(self) -> usize {
        self.queued_bytes
    }

    #[must_use]
    pub const fn admitted_frames(self) -> u64 {
        self.admitted_frames
    }

    #[must_use]
    pub const fn rejected_oversize(self) -> u64 {
        self.rejected_oversize
    }

    #[must_use]
    pub const fn rejected_items_full(self) -> u64 {
        self.rejected_items_full
    }

    #[must_use]
    pub const fn rejected_bytes_full(self) -> u64 {
        self.rejected_bytes_full
    }

    #[must_use]
    pub const fn rejected_malformed(self) -> u64 {
        self.rejected_malformed
    }

    #[must_use]
    pub const fn rejected_stale(self) -> u64 {
        self.rejected_stale
    }

    #[must_use]
    pub const fn rejected_closed(self) -> u64 {
        self.rejected_closed
    }
}

pub(crate) struct IngressBudget {
    limits: IngressLimits,
    queued_items: AtomicUsize,
    queued_bytes: AtomicUsize,
    counters: IngressCounters,
}

impl IngressBudget {
    pub(crate) fn new(limits: IngressLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            queued_items: AtomicUsize::new(0),
            queued_bytes: AtomicUsize::new(0),
            counters: IngressCounters::default(),
        })
    }

    pub(crate) fn try_reserve(self: &Arc<Self>, bytes: usize) -> Result<IngressLease, OfferError> {
        if bytes > self.limits.max_frame_bytes() {
            self.counters
                .rejected_oversize
                .fetch_add(1, Ordering::Relaxed);
            return Err(OfferError::Oversize);
        }
        self.queued_items
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.limits.max_items()).then_some(current + 1)
            })
            .map_err(|_| {
                self.counters
                    .rejected_items_full
                    .fetch_add(1, Ordering::Relaxed);
                OfferError::ItemsFull
            })?;

        let bytes_result =
            self.queued_bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(bytes)
                        .filter(|next| *next <= self.limits.max_bytes())
                });
        if bytes_result.is_err() {
            self.queued_items.fetch_sub(1, Ordering::AcqRel);
            self.counters
                .rejected_bytes_full
                .fetch_add(1, Ordering::Relaxed);
            return Err(OfferError::BytesFull);
        }

        Ok(IngressLease {
            owner: Arc::clone(self),
            bytes,
        })
    }

    pub(crate) fn admitted(&self) {
        self.counters
            .admitted_frames
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rejected_malformed(&self) {
        self.counters
            .rejected_malformed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rejected_stale(&self) {
        self.counters.rejected_stale.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rejected_closed(&self) {
        self.counters
            .rejected_closed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> FabricIngressSnapshot {
        FabricIngressSnapshot {
            queued_items: self.queued_items.load(Ordering::Acquire),
            queued_bytes: self.queued_bytes.load(Ordering::Acquire),
            admitted_frames: self.counters.admitted_frames.load(Ordering::Relaxed),
            rejected_oversize: self.counters.rejected_oversize.load(Ordering::Relaxed),
            rejected_items_full: self.counters.rejected_items_full.load(Ordering::Relaxed),
            rejected_bytes_full: self.counters.rejected_bytes_full.load(Ordering::Relaxed),
            rejected_malformed: self.counters.rejected_malformed.load(Ordering::Relaxed),
            rejected_stale: self.counters.rejected_stale.load(Ordering::Relaxed),
            rejected_closed: self.counters.rejected_closed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
struct IngressCounters {
    admitted_frames: AtomicU64,
    rejected_oversize: AtomicU64,
    rejected_items_full: AtomicU64,
    rejected_bytes_full: AtomicU64,
    rejected_malformed: AtomicU64,
    rejected_stale: AtomicU64,
    rejected_closed: AtomicU64,
}

pub(crate) struct IngressLease {
    owner: Arc<IngressBudget>,
    bytes: usize,
}

impl Drop for IngressLease {
    fn drop(&mut self) {
        self.owner
            .queued_bytes
            .fetch_sub(self.bytes, Ordering::AcqRel);
        self.owner.queued_items.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OfferError {
    Oversize,
    ItemsFull,
    BytesFull,
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{
        IngressBudget, IngressLimitError, IngressLimits, MAX_INGRESS_BYTES, MAX_INGRESS_ITEMS,
        OfferError,
    };

    fn limits(items: usize, bytes: usize, frame: usize) -> IngressLimits {
        IngressLimits::try_new(items, bytes, frame, 64, Duration::from_secs(1)).unwrap()
    }

    #[test]
    fn items_and_bytes_are_independently_bounded_and_released() {
        let budget = IngressBudget::new(limits(2, 12, 10));
        let first = budget.try_reserve(7).unwrap();
        assert_eq!(budget.try_reserve(6).err(), Some(OfferError::BytesFull));
        let second = budget.try_reserve(5).unwrap();
        assert_eq!(budget.try_reserve(1).err(), Some(OfferError::ItemsFull));
        let snapshot = budget.snapshot();
        assert_eq!(snapshot.queued_items(), 2);
        assert_eq!(snapshot.queued_bytes(), 12);
        assert_eq!(snapshot.rejected_bytes_full(), 1);
        assert_eq!(snapshot.rejected_items_full(), 1);
        drop(first);
        drop(second);
        assert_eq!(budget.snapshot().queued_items(), 0);
        assert_eq!(budget.snapshot().queued_bytes(), 0);
    }

    #[test]
    fn one_frame_cannot_bypass_the_frame_bound() {
        let budget = IngressBudget::new(limits(2, 20, 8));
        assert_eq!(budget.try_reserve(9).err(), Some(OfferError::Oversize));
        assert_eq!(budget.snapshot().rejected_oversize(), 1);
        assert_eq!(budget.snapshot().queued_items(), 0);
    }

    #[test]
    fn wire_carried_capacities_have_platform_independent_bounds() {
        assert_eq!(
            IngressLimits::try_new(MAX_INGRESS_ITEMS + 1, 512, 256, 256, Duration::from_secs(1),),
            Err(IngressLimitError::ItemsExceedProtocolBound)
        );
        assert_eq!(
            IngressLimits::try_new(1, MAX_INGRESS_BYTES + 1, 256, 256, Duration::from_secs(1),),
            Err(IngressLimitError::BytesExceedProtocolBound)
        );
    }
}
