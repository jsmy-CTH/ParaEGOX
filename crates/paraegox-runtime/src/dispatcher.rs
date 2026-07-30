//! Pure, synchronous loop-domain dispatch selection and permit accounting.
//!
//! This module owns no payload and performs no waiting. The single runtime
//! owner supplies bounded mailbox readiness views and performs any selected
//! dequeue synchronously after a domain permit has been acquired.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;

use paraegox_runtime_contracts::assignment::MailboxRef;
use paraegox_runtime_contracts::execution::{MAX_MINIMUM_SERVICE_WEIGHT, MAX_SERVICE_COST_TOKENS};

use crate::mailbox::MailboxHeadReadiness;

pub(crate) const MAX_DISPATCH_SLOTS: usize = 256;
const CLASS_COUNT: usize = 4;
const MAX_DEFICIT: u64 = 1_u64 << 48;
const MAX_CLASS_QUANTUM: u32 = MAX_MINIMUM_SERVICE_WEIGHT * MAX_DISPATCH_SLOTS as u32;
const MAX_CLASS_BURST: u32 = u16::MAX as u32 * MAX_DISPATCH_SLOTS as u32;

/// Runtime-internal dispatch class. The PXTE contract owner maps into this
/// primitive at the admission boundary; this module does not interpret wire
/// or public policy types.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum DispatchClass {
    Control,
    Interactive,
    Stream,
    Background,
}

impl DispatchClass {
    const ALL: [Self; CLASS_COUNT] = [
        Self::Control,
        Self::Interactive,
        Self::Stream,
        Self::Background,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Control => 0,
            Self::Interactive => 1,
            Self::Stream => 2,
            Self::Background => 3,
        }
    }

    const fn is_control(self) -> bool {
        matches!(self, Self::Control)
    }
}

/// Bounded outer-class quantum and consecutive-service cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DispatchClassPolicy {
    quantum: u32,
    max_burst: u32,
}

impl DispatchClassPolicy {
    pub(crate) fn try_new(quantum: u32, max_burst: u32) -> Result<Self, DispatcherError> {
        if quantum == 0 || quantum > MAX_CLASS_QUANTUM {
            return Err(DispatcherError::InvalidWeight);
        }
        if max_burst == 0 || max_burst > MAX_CLASS_BURST {
            return Err(DispatcherError::InvalidBurst);
        }
        Ok(Self { quantum, max_burst })
    }
}

/// Immutable scheduling inputs for one registered mailbox slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DispatchSlotSpec {
    mailbox: MailboxRef,
    class: DispatchClass,
    cost: u32,
    weight: u32,
    max_burst: u32,
}

impl DispatchSlotSpec {
    pub(crate) fn try_new(
        mailbox: MailboxRef,
        class: DispatchClass,
        cost: u32,
        weight: u32,
        max_burst: u16,
    ) -> Result<Self, DispatcherError> {
        if cost == 0 || cost > MAX_SERVICE_COST_TOKENS {
            return Err(DispatcherError::InvalidCost);
        }
        if weight == 0 || weight > MAX_MINIMUM_SERVICE_WEIGHT {
            return Err(DispatcherError::InvalidWeight);
        }
        if max_burst == 0 {
            return Err(DispatcherError::InvalidBurst);
        }
        Ok(Self {
            mailbox,
            class,
            cost,
            weight,
            max_burst: u32::from(max_burst),
        })
    }
}

/// Per-step mailbox state supplied by the single loop-domain owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DispatchReadiness {
    mailbox: MailboxRef,
    head: MailboxHeadReadiness,
}

impl DispatchReadiness {
    #[must_use]
    pub(crate) const fn new(mailbox: MailboxRef, head: MailboxHeadReadiness) -> Self {
        Self { mailbox, head }
    }
}

#[derive(Debug)]
struct DispatchSlot {
    mailbox: MailboxRef,
    class: DispatchClass,
    cost: u32,
    weight: u32,
    deficit: u64,
    max_burst: u32,
    cursor: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectionPath {
    DirectScan,
    HierarchicalDeficit,
}

/// Selected mailbox metadata. It never owns or borrows a Message payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DispatchSelection {
    mailbox: MailboxRef,
    class: DispatchClass,
    cost: u32,
    path: SelectionPath,
}

impl DispatchSelection {
    #[must_use]
    pub(crate) const fn mailbox(self) -> MailboxRef {
        self.mailbox
    }

    #[must_use]
    pub(crate) const fn class(self) -> DispatchClass {
        self.class
    }

    #[must_use]
    pub(crate) const fn cost(self) -> u32 {
        self.cost
    }

    #[cfg(test)]
    const fn path(self) -> SelectionPath {
        self.path
    }
}

/// Stable identity for one runtime-owned permit ledger.
#[derive(Clone, Debug)]
pub(crate) struct DomainPermitLedgerId {
    domain: [u8; 16],
    domain_epoch: u64,
    marker: Arc<()>,
}

impl DomainPermitLedgerId {
    #[must_use]
    pub(crate) fn new(domain: [u8; 16], domain_epoch: u64) -> Self {
        Self {
            domain,
            domain_epoch,
            marker: Arc::new(()),
        }
    }
}

impl PartialEq for DomainPermitLedgerId {
    fn eq(&self, other: &Self) -> bool {
        self.domain == other.domain
            && self.domain_epoch == other.domain_epoch
            && Arc::ptr_eq(&self.marker, &other.marker)
    }
}

impl Eq for DomainPermitLedgerId {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PermitPool {
    Shared,
    ControlReserved,
}

/// An explicit, non-Clone permit capability. Dropping an active token leaks
/// capacity conservatively; only the originating ledger can release it.
#[must_use = "an active domain permit must be released by its originating ledger"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DomainPermitToken {
    ledger: DomainPermitLedgerId,
    permit_id: u64,
    pool: PermitPool,
    active: bool,
}

impl DomainPermitToken {
    #[must_use]
    pub(crate) const fn is_active(&self) -> bool {
        self.active
    }
}

/// Fixed-width read-only permit accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DomainPermitSnapshot {
    total: u32,
    control_reserved: u32,
    shared_in_use: u32,
    control_reserved_in_use: u32,
}

impl DomainPermitSnapshot {
    #[must_use]
    pub(crate) const fn total(self) -> u32 {
        self.total
    }

    #[must_use]
    pub(crate) const fn control_reserved(self) -> u32 {
        self.control_reserved
    }

    #[must_use]
    pub(crate) const fn shared_in_use(self) -> u32 {
        self.shared_in_use
    }

    #[must_use]
    pub(crate) const fn control_reserved_in_use(self) -> u32 {
        self.control_reserved_in_use
    }

    #[must_use]
    pub(crate) const fn in_use(self) -> u32 {
        self.shared_in_use + self.control_reserved_in_use
    }

    #[must_use]
    pub(crate) const fn available(self) -> u32 {
        self.total - self.in_use()
    }
}

/// Single-owner permit accounting for one loop domain.
pub(crate) struct DomainPermitLedger {
    id: DomainPermitLedgerId,
    total: u32,
    control_reserved: u32,
    shared_in_use: u32,
    control_reserved_in_use: u32,
    next_permit_id: u64,
    active: BTreeMap<u64, PermitPool>,
}

impl DomainPermitLedger {
    pub(crate) fn try_new(
        id: DomainPermitLedgerId,
        total: u32,
        control_reserved: u32,
    ) -> Result<Self, PermitError> {
        if total == 0 || control_reserved > total {
            return Err(PermitError::InvalidCapacity);
        }
        Ok(Self {
            id,
            total,
            control_reserved,
            shared_in_use: 0,
            control_reserved_in_use: 0,
            next_permit_id: 0,
            active: BTreeMap::new(),
        })
    }

    #[must_use]
    pub(crate) fn can_acquire(&self, class: DispatchClass) -> bool {
        if class.is_control() && self.control_reserved_in_use < self.control_reserved {
            return true;
        }
        self.shared_in_use < self.total - self.control_reserved
    }

    pub(crate) fn try_acquire(
        &mut self,
        class: DispatchClass,
    ) -> Result<Option<DomainPermitToken>, PermitError> {
        self.validate_state()?;
        let pool = if class.is_control() && self.control_reserved_in_use < self.control_reserved {
            PermitPool::ControlReserved
        } else if self.shared_in_use < self.total - self.control_reserved {
            PermitPool::Shared
        } else {
            return Ok(None);
        };
        let permit_id = self
            .next_permit_id
            .checked_add(1)
            .ok_or(PermitError::CounterOverflow)?;
        let previous = self.active.insert(permit_id, pool);
        if previous.is_some() {
            return Err(PermitError::StateInconsistent);
        }
        match pool {
            PermitPool::Shared => {
                self.shared_in_use = self
                    .shared_in_use
                    .checked_add(1)
                    .ok_or(PermitError::CounterOverflow)?;
            }
            PermitPool::ControlReserved => {
                self.control_reserved_in_use = self
                    .control_reserved_in_use
                    .checked_add(1)
                    .ok_or(PermitError::CounterOverflow)?;
            }
        }
        self.next_permit_id = permit_id;
        Ok(Some(DomainPermitToken {
            ledger: self.id.clone(),
            permit_id,
            pool,
            active: true,
        }))
    }

    pub(crate) fn release(&mut self, token: &mut DomainPermitToken) -> Result<(), PermitError> {
        self.validate_state()?;
        if !token.active {
            return Err(PermitError::AlreadyReleased);
        }
        if token.ledger != self.id {
            return Err(PermitError::LedgerMismatch);
        }
        let Some(pool) = self.active.get(&token.permit_id).copied() else {
            return Err(PermitError::TokenMismatch);
        };
        if pool != token.pool {
            return Err(PermitError::TokenMismatch);
        }
        match pool {
            PermitPool::Shared => {
                self.shared_in_use = self
                    .shared_in_use
                    .checked_sub(1)
                    .ok_or(PermitError::StateInconsistent)?;
            }
            PermitPool::ControlReserved => {
                self.control_reserved_in_use = self
                    .control_reserved_in_use
                    .checked_sub(1)
                    .ok_or(PermitError::StateInconsistent)?;
            }
        }
        self.active.remove(&token.permit_id);
        token.active = false;
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Result<DomainPermitSnapshot, PermitError> {
        self.validate_state()?;
        Ok(DomainPermitSnapshot {
            total: self.total,
            control_reserved: self.control_reserved,
            shared_in_use: self.shared_in_use,
            control_reserved_in_use: self.control_reserved_in_use,
        })
    }

    fn validate_state(&self) -> Result<(), PermitError> {
        let shared_capacity = self
            .total
            .checked_sub(self.control_reserved)
            .ok_or(PermitError::StateInconsistent)?;
        if self.total == 0
            || self.shared_in_use > shared_capacity
            || self.control_reserved_in_use > self.control_reserved
        {
            return Err(PermitError::StateInconsistent);
        }
        let active =
            u32::try_from(self.active.len()).map_err(|_| PermitError::StateInconsistent)?;
        let counted = self
            .shared_in_use
            .checked_add(self.control_reserved_in_use)
            .ok_or(PermitError::StateInconsistent)?;
        if active != counted {
            return Err(PermitError::StateInconsistent);
        }
        let recomputed_shared = self
            .active
            .values()
            .filter(|pool| **pool == PermitPool::Shared)
            .count();
        let recomputed_reserved = self.active.len() - recomputed_shared;
        if usize::try_from(self.shared_in_use).ok() != Some(recomputed_shared)
            || usize::try_from(self.control_reserved_in_use).ok() != Some(recomputed_reserved)
        {
            return Err(PermitError::StateInconsistent);
        }
        Ok(())
    }
}

/// A selected mailbox plus the already-acquired domain permit.
#[must_use = "a dispatch grant owns an active domain permit"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DispatchGrant {
    selection: DispatchSelection,
    permit: DomainPermitToken,
}

impl DispatchGrant {
    #[must_use]
    pub(crate) const fn selection(&self) -> DispatchSelection {
        self.selection
    }

    pub(crate) fn into_parts(self) -> (DispatchSelection, DomainPermitToken) {
        (self.selection, self.permit)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DispatchIdleReason {
    NoReadyMailbox,
    NoDomainPermit,
}

#[must_use = "a selected decision owns an active domain permit"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DispatchDecision {
    Selected(DispatchGrant),
    Idle(DispatchIdleReason),
}

/// Pure, single-owner hierarchical weighted-deficit scheduler.
pub(crate) struct DispatchPolicy {
    slots: Box<[DispatchSlot]>,
    classes: [DispatchClassPolicy; CLASS_COUNT],
    class_deficit: [u64; CLASS_COUNT],
    class_cursor: usize,
    class_visit_open: bool,
    slot_cursor: [usize; CLASS_COUNT],
    last_class: Option<DispatchClass>,
    class_burst: u32,
    last_slot: Option<usize>,
    slot_burst: u32,
    direct_scan: bool,
    direct_cursor: usize,
}

impl DispatchPolicy {
    pub(crate) fn try_new(
        classes: [DispatchClassPolicy; CLASS_COUNT],
        specs: Vec<DispatchSlotSpec>,
    ) -> Result<Self, DispatcherError> {
        if specs.is_empty() {
            return Err(DispatcherError::NoSlots);
        }
        if specs.len() > MAX_DISPATCH_SLOTS {
            return Err(DispatcherError::TooManySlots);
        }
        let mut mailboxes = specs.iter().map(|spec| spec.mailbox).collect::<Vec<_>>();
        mailboxes.sort_unstable();
        if mailboxes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DispatcherError::DuplicateMailbox);
        }
        let direct_scan = specs.iter().all(|spec| {
            spec.class == specs[0].class
                && spec.cost == specs[0].cost
                && spec.weight == specs[0].weight
        });
        let slots = specs
            .into_iter()
            .enumerate()
            .map(|(cursor, spec)| {
                let cursor = u16::try_from(cursor).map_err(|_| DispatcherError::TooManySlots)?;
                Ok(DispatchSlot {
                    mailbox: spec.mailbox,
                    class: spec.class,
                    cost: spec.cost,
                    weight: spec.weight,
                    deficit: 0,
                    max_burst: spec.max_burst,
                    cursor,
                })
            })
            .collect::<Result<Vec<_>, DispatcherError>>()?
            .into_boxed_slice();
        Ok(Self {
            slots,
            classes,
            class_deficit: [0; CLASS_COUNT],
            class_cursor: 0,
            class_visit_open: false,
            slot_cursor: [0; CLASS_COUNT],
            last_class: None,
            class_burst: 0,
            last_slot: None,
            slot_burst: 0,
            direct_scan,
            direct_cursor: 0,
        })
    }

    #[must_use]
    pub(crate) fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Selects a ready mailbox only after acquiring a suitable domain permit.
    pub(crate) fn try_select_and_acquire(
        &mut self,
        readiness: &[DispatchReadiness],
        permits: &mut DomainPermitLedger,
    ) -> Result<DispatchDecision, DispatcherError> {
        let ready = self.validate_readiness(readiness)?;
        if !ready.iter().any(|value| *value) {
            return Ok(DispatchDecision::Idle(DispatchIdleReason::NoReadyMailbox));
        }
        let eligible = ready
            .iter()
            .enumerate()
            .map(|(index, value)| *value && permits.can_acquire(self.slots[index].class))
            .collect::<Vec<_>>();
        if !eligible.iter().any(|value| *value) {
            return Ok(DispatchDecision::Idle(DispatchIdleReason::NoDomainPermit));
        }

        let (slot_index, path) = if self.direct_scan {
            (self.select_direct(&eligible)?, SelectionPath::DirectScan)
        } else {
            (
                self.select_hierarchical(&eligible)?,
                SelectionPath::HierarchicalDeficit,
            )
        };
        let slot = &self.slots[slot_index];
        let Some(permit) = permits
            .try_acquire(slot.class)
            .map_err(DispatcherError::Permit)?
        else {
            return Err(DispatcherError::PermitStateChanged);
        };
        Ok(DispatchDecision::Selected(DispatchGrant {
            selection: DispatchSelection {
                mailbox: slot.mailbox,
                class: slot.class,
                cost: slot.cost,
                path,
            },
            permit,
        }))
    }

    fn validate_readiness(
        &self,
        readiness: &[DispatchReadiness],
    ) -> Result<Vec<bool>, DispatcherError> {
        if readiness.len() > MAX_DISPATCH_SLOTS {
            return Err(DispatcherError::TooManyReadinessHints);
        }
        let mut ready = vec![false; self.slots.len()];
        let mut seen = vec![false; self.slots.len()];
        for input in readiness {
            let Some(index) = self
                .slots
                .iter()
                .position(|slot| slot.mailbox == input.mailbox)
            else {
                return Err(DispatcherError::UnknownMailbox);
            };
            if seen[index] {
                return Err(DispatcherError::DuplicateReadinessHint);
            }
            if input
                .head
                .hint()
                .is_some_and(|hint| hint.mailbox() != input.mailbox)
            {
                return Err(DispatcherError::ReadinessMailboxMismatch);
            }
            seen[index] = true;
            ready[index] = input.head.is_dispatchable();
        }
        Ok(ready)
    }

    fn select_direct(&mut self, eligible: &[bool]) -> Result<usize, DispatcherError> {
        for offset in 0..self.slots.len() {
            let index = (self.direct_cursor + offset) % self.slots.len();
            if eligible[index] {
                self.direct_cursor = (index + 1) % self.slots.len();
                return Ok(index);
            }
        }
        Err(DispatcherError::StateInconsistent)
    }

    fn select_hierarchical(&mut self, eligible: &[bool]) -> Result<usize, DispatcherError> {
        if let Some(slot_index) = self.select_hierarchical_pass(eligible)? {
            return Ok(slot_index);
        }

        self.fast_forward_empty_class_rounds(eligible)?;
        self.select_hierarchical_pass(eligible)?
            .ok_or(DispatcherError::StateInconsistent)
    }

    fn select_hierarchical_pass(
        &mut self,
        eligible: &[bool],
    ) -> Result<Option<usize>, DispatcherError> {
        let mut burst_fallback = None;
        for _ in 0..CLASS_COUNT {
            let class_index = self.class_cursor;
            let class = DispatchClass::ALL[class_index];
            if !self.class_has_eligible(class, eligible) {
                self.advance_class_visit(class_index);
                continue;
            }
            if !self.class_visit_open {
                self.credit_class_visit(class_index)?;
                self.class_visit_open = true;
            }
            let slot_index = self.prepare_slot_in_class(class, eligible)?;
            let cost = u64::from(self.slots[slot_index].cost);
            if self.class_deficit[class_index] < cost {
                self.advance_class_visit(class_index);
                continue;
            }
            if self.class_burst_exhausted(class) && self.has_other_eligible_class(class, eligible) {
                burst_fallback = Some((class_index, slot_index));
                self.advance_class_visit(class_index);
                continue;
            }
            return self
                .commit_class_service(class_index, slot_index, eligible)
                .map(Some);
        }

        // A burst cap only yields to work that can actually run. If every
        // alternative is still accumulating class credit, continue the sole
        // affordable class without adding a second quantum in this turn.
        if let Some((class_index, slot_index)) = burst_fallback {
            return self
                .commit_class_service(class_index, slot_index, eligible)
                .map(Some);
        }
        Ok(None)
    }

    fn fast_forward_empty_class_rounds(
        &mut self,
        eligible: &[bool],
    ) -> Result<(), DispatcherError> {
        if self.class_visit_open {
            return Err(DispatcherError::StateInconsistent);
        }

        let mut visits_until_service = None;
        for class in DispatchClass::ALL {
            if !self.class_has_eligible(class, eligible) {
                continue;
            }
            let class_index = class.index();
            let slot_index = self.prepare_slot_in_class(class, eligible)?;
            let missing = u64::from(self.slots[slot_index].cost)
                .checked_sub(self.class_deficit[class_index])
                .filter(|missing| *missing > 0)
                .ok_or(DispatcherError::StateInconsistent)?;
            let quantum = u64::from(self.classes[class_index].quantum);
            let visits = missing
                .checked_add(quantum - 1)
                .ok_or(DispatcherError::CounterOverflow)?
                / quantum;
            visits_until_service =
                Some(visits_until_service.map_or(visits, |current: u64| current.min(visits)));
        }

        let empty_rounds = visits_until_service
            .ok_or(DispatcherError::StateInconsistent)?
            .checked_sub(1)
            .ok_or(DispatcherError::StateInconsistent)?;
        if empty_rounds == 0 {
            return Ok(());
        }
        for class in DispatchClass::ALL {
            if !self.class_has_eligible(class, eligible) {
                continue;
            }
            let class_index = class.index();
            let credit = empty_rounds
                .checked_mul(u64::from(self.classes[class_index].quantum))
                .ok_or(DispatcherError::CounterOverflow)?;
            self.class_deficit[class_index] = self.class_deficit[class_index]
                .checked_add(credit)
                .ok_or(DispatcherError::CounterOverflow)?
                .min(MAX_DEFICIT);
        }
        Ok(())
    }

    fn commit_class_service(
        &mut self,
        class_index: usize,
        slot_index: usize,
        eligible: &[bool],
    ) -> Result<usize, DispatcherError> {
        let class = DispatchClass::ALL[class_index];
        let cost = u64::from(self.slots[slot_index].cost);
        self.class_deficit[class_index] = self.class_deficit[class_index]
            .checked_sub(cost)
            .ok_or(DispatcherError::StateInconsistent)?;
        self.commit_slot_service(slot_index)?;
        self.record_class_service(class);
        let keep_class = self.class_burst < self.classes[class_index].max_burst
            && self.class_deficit[class_index] >= self.minimum_eligible_cost(class, eligible);
        if keep_class {
            self.class_cursor = class_index;
            self.class_visit_open = true;
        } else {
            self.advance_class_visit(class_index);
        }
        Ok(slot_index)
    }

    fn credit_class_visit(&mut self, class_index: usize) -> Result<(), DispatcherError> {
        self.class_deficit[class_index] = self.class_deficit[class_index]
            .checked_add(u64::from(self.classes[class_index].quantum))
            .ok_or(DispatcherError::CounterOverflow)?
            .min(MAX_DEFICIT);
        Ok(())
    }

    fn advance_class_visit(&mut self, class_index: usize) {
        self.class_cursor = (class_index + 1) % CLASS_COUNT;
        self.class_visit_open = false;
    }

    fn prepare_slot_in_class(
        &mut self,
        class: DispatchClass,
        eligible: &[bool],
    ) -> Result<usize, DispatcherError> {
        let class_index = class.index();
        let start = self.slot_cursor[class_index] % self.slots.len();
        let mut required_rounds = None;
        for offset in 0..self.slots.len() {
            let index = (start + offset) % self.slots.len();
            if !eligible[index] || self.slots[index].class != class {
                continue;
            }
            if self.slot_burst_exhausted(index)
                && self.has_other_eligible_slot(index, class, eligible)
            {
                continue;
            }
            let slot = &self.slots[index];
            let cost = u64::from(slot.cost);
            let missing = cost.saturating_sub(slot.deficit);
            let weight = u64::from(slot.weight);
            let rounds = if missing == 0 {
                0
            } else {
                missing
                    .checked_add(weight - 1)
                    .ok_or(DispatcherError::CounterOverflow)?
                    / weight
            };
            required_rounds = Some(required_rounds.map_or(rounds, |value: u64| value.min(rounds)));
        }
        let Some(required_rounds) = required_rounds else {
            return Err(DispatcherError::StateInconsistent);
        };

        if required_rounds > 0 {
            for (index, slot) in self.slots.iter_mut().enumerate() {
                if eligible[index] && slot.class == class {
                    let credit = required_rounds
                        .checked_mul(u64::from(slot.weight))
                        .ok_or(DispatcherError::CounterOverflow)?;
                    slot.deficit = slot
                        .deficit
                        .checked_add(credit)
                        .ok_or(DispatcherError::CounterOverflow)?
                        .min(MAX_DEFICIT);
                }
            }
        }

        for offset in 0..self.slots.len() {
            let index = (start + offset) % self.slots.len();
            if !eligible[index] || self.slots[index].class != class {
                continue;
            }
            if self.slot_burst_exhausted(index)
                && self.has_other_eligible_slot(index, class, eligible)
            {
                continue;
            }
            let cost = u64::from(self.slots[index].cost);
            if self.slots[index].deficit >= cost {
                return Ok(index);
            }
        }
        Err(DispatcherError::StateInconsistent)
    }

    fn commit_slot_service(&mut self, index: usize) -> Result<(), DispatcherError> {
        let cost = u64::from(self.slots[index].cost);
        self.slots[index].deficit = self.slots[index]
            .deficit
            .checked_sub(cost)
            .ok_or(DispatcherError::StateInconsistent)?;
        let class_index = self.slots[index].class.index();
        let max_burst = self.slots[index].max_burst;
        let remaining_deficit = self.slots[index].deficit;
        self.record_slot_service(index);
        let repeat = self.slot_burst < max_burst && remaining_deficit >= cost;
        self.slot_cursor[class_index] = if repeat {
            index
        } else {
            (index + 1) % self.slots.len()
        };
        Ok(())
    }

    fn class_has_eligible(&self, class: DispatchClass, eligible: &[bool]) -> bool {
        self.slots
            .iter()
            .enumerate()
            .any(|(index, slot)| eligible[index] && slot.class == class)
    }

    fn has_other_eligible_class(&self, class: DispatchClass, eligible: &[bool]) -> bool {
        self.slots
            .iter()
            .enumerate()
            .any(|(index, slot)| eligible[index] && slot.class != class)
    }

    fn has_other_eligible_slot(
        &self,
        selected: usize,
        class: DispatchClass,
        eligible: &[bool],
    ) -> bool {
        self.slots
            .iter()
            .enumerate()
            .any(|(index, slot)| index != selected && eligible[index] && slot.class == class)
    }

    fn minimum_eligible_cost(&self, class: DispatchClass, eligible: &[bool]) -> u64 {
        self.slots
            .iter()
            .enumerate()
            .filter(|(index, slot)| eligible[*index] && slot.class == class)
            .map(|(_, slot)| u64::from(slot.cost))
            .min()
            .unwrap_or(u64::MAX)
    }

    fn class_burst_exhausted(&self, class: DispatchClass) -> bool {
        self.last_class == Some(class) && self.class_burst >= self.classes[class.index()].max_burst
    }

    fn slot_burst_exhausted(&self, index: usize) -> bool {
        self.last_slot == Some(index) && self.slot_burst >= self.slots[index].max_burst
    }

    fn record_class_service(&mut self, class: DispatchClass) {
        if self.last_class == Some(class) {
            self.class_burst = self.class_burst.saturating_add(1);
        } else {
            self.last_class = Some(class);
            self.class_burst = 1;
        }
    }

    fn record_slot_service(&mut self, index: usize) {
        if self.last_slot == Some(index) {
            self.slot_burst = self.slot_burst.saturating_add(1);
        } else {
            self.last_slot = Some(index);
            self.slot_burst = 1;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PermitError {
    InvalidCapacity,
    CounterOverflow,
    StateInconsistent,
    LedgerMismatch,
    TokenMismatch,
    AlreadyReleased,
}

impl fmt::Display for PermitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCapacity => "invalid domain permit capacity",
            Self::CounterOverflow => "domain permit counter overflow",
            Self::StateInconsistent => "domain permit state is inconsistent",
            Self::LedgerMismatch => "domain permit belongs to another ledger",
            Self::TokenMismatch => "domain permit token does not match ledger state",
            Self::AlreadyReleased => "domain permit was already released",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PermitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DispatcherError {
    NoSlots,
    TooManySlots,
    DuplicateMailbox,
    InvalidCost,
    InvalidWeight,
    InvalidBurst,
    TooManyReadinessHints,
    DuplicateReadinessHint,
    UnknownMailbox,
    ReadinessMailboxMismatch,
    CounterOverflow,
    StateInconsistent,
    PermitStateChanged,
    Permit(PermitError),
}

impl fmt::Display for DispatcherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NoSlots => "dispatch policy requires at least one mailbox slot",
            Self::TooManySlots => "dispatch policy exceeds the fixed slot bound",
            Self::DuplicateMailbox => "dispatch policy contains a duplicate mailbox",
            Self::InvalidCost => "dispatch cost is outside the bounded range",
            Self::InvalidWeight => "dispatch weight is outside the bounded range",
            Self::InvalidBurst => "dispatch burst is outside the bounded range",
            Self::TooManyReadinessHints => "dispatch readiness exceeds the fixed slot bound",
            Self::DuplicateReadinessHint => "dispatch readiness repeats one mailbox",
            Self::UnknownMailbox => "dispatch readiness names an unknown mailbox",
            Self::ReadinessMailboxMismatch => "dispatch readiness head belongs to another mailbox",
            Self::CounterOverflow => "dispatch counter overflow",
            Self::StateInconsistent => "dispatch state is inconsistent",
            Self::PermitStateChanged => "domain permit state changed during synchronous selection",
            Self::Permit(error) => return error.fmt(formatter),
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DispatcherError {}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::time::{
        BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant,
    };
    use paraegox_runtime_contracts::assignment::{
        InteractionKind, MailboxRef, MailboxSpec, OverflowPolicy, SchemaRef,
    };
    use paraegox_runtime_contracts::execution::{
        MAX_MINIMUM_SERVICE_WEIGHT, MAX_SERVICE_COST_TOKENS,
    };

    use crate::mailbox::{
        DispatchOutcome as MailboxDispatchOutcome, EnqueueOutcome, Mailbox, MailboxHeadReadiness,
        MessageId, PayloadHandle, TerminalReason, ValidatedMessage,
    };

    use super::{
        DispatchClass, DispatchClassPolicy, DispatchDecision, DispatchIdleReason, DispatchPolicy,
        DispatchReadiness, DispatchSlotSpec, DispatcherError, DomainPermitLedger,
        DomainPermitLedgerId, DomainPermitToken, MAX_CLASS_BURST, MAX_CLASS_QUANTUM,
        MAX_DISPATCH_SLOTS, PermitError, SelectionPath,
    };

    const CLOCK_DOMAIN: u8 = 0x31;
    const CLOCK_GENERATION: u64 = 7;

    fn mailbox_ref(value: u16) -> MailboxRef {
        let mut bytes = [0_u8; 16];
        bytes[..2].copy_from_slice(&value.to_be_bytes());
        MailboxRef::from_bytes(bytes)
    }

    fn schema() -> SchemaRef {
        let Ok(schema) = SchemaRef::try_new([0x41; 16], 1, Digest32::from_bytes([0x42; 32])) else {
            panic!("test schema must be valid");
        };
        schema
    }

    fn generation() -> ClockGeneration {
        let Ok(value) = ClockGeneration::try_new(CLOCK_GENERATION) else {
            panic!("test generation must be nonzero");
        };
        value
    }

    fn reading(now: u64) -> ClockReading {
        ClockReading::new(
            ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16]),
            generation(),
            MonotonicInstant::from_ticks(now),
        )
    }

    fn deadline(ticks: u64) -> paraegox_kernel::time::MonotonicDeadline {
        let Ok(value) = reading(0).try_deadline_after(BoundedDuration::from_nanos(ticks)) else {
            panic!("test deadline must be valid");
        };
        value
    }

    fn mailbox_with_message(
        identity: u16,
        fresh_until: u64,
        run_deadline: u64,
        queue_age: u64,
    ) -> Mailbox {
        let Ok(spec) = MailboxSpec::try_new(
            2,
            8,
            BoundedDuration::from_nanos(queue_age),
            1,
            8,
            OverflowPolicy::RejectNew,
        ) else {
            panic!("test mailbox spec must be valid");
        };
        let Ok(mut mailbox) = Mailbox::try_new(
            mailbox_ref(identity),
            schema(),
            InteractionKind::Signal,
            spec,
            ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16]),
            generation(),
        ) else {
            panic!("test mailbox must be valid");
        };
        let Ok(payload) = PayloadHandle::try_from_vec(vec![u8::try_from(identity).unwrap_or(1); 2])
        else {
            panic!("test payload must be valid");
        };
        let message = ValidatedMessage::new_with_deadlines(
            MessageId::from_bytes([u8::try_from(identity).unwrap_or(1); 16]),
            schema(),
            InteractionKind::Signal,
            None,
            deadline(fresh_until),
            deadline(run_deadline),
            payload,
        );
        let Ok(report) = mailbox.try_offer(message, reading(0)) else {
            panic!("test offer must be structurally valid");
        };
        assert!(matches!(report.outcome(), EnqueueOutcome::Admitted));
        mailbox
    }

    fn readiness(mailbox: &Mailbox, now: u64) -> DispatchReadiness {
        let Ok(head) = mailbox.head_readiness(reading(now)) else {
            panic!("test readiness must be structurally valid");
        };
        DispatchReadiness::new(mailbox.reference(), head)
    }

    fn detached_ready(identity: u16) -> DispatchReadiness {
        let mailbox = mailbox_with_message(identity, 100, 100, 100);
        readiness(&mailbox, 0)
    }

    fn class_policy(quantum: u32, max_burst: u32) -> DispatchClassPolicy {
        DispatchClassPolicy::try_new(quantum, max_burst)
            .unwrap_or_else(|error| panic!("test class policy failed: {error}"))
    }

    fn class_policies() -> [DispatchClassPolicy; 4] {
        [
            class_policy(8, 4),
            class_policy(4, 3),
            class_policy(2, 2),
            class_policy(1, 1),
        ]
    }

    fn slot(
        identity: u16,
        class: DispatchClass,
        cost: u32,
        weight: u32,
        max_burst: u16,
    ) -> DispatchSlotSpec {
        DispatchSlotSpec::try_new(mailbox_ref(identity), class, cost, weight, max_burst)
            .unwrap_or_else(|error| panic!("test slot failed: {error}"))
    }

    fn policy(specs: Vec<DispatchSlotSpec>) -> DispatchPolicy {
        DispatchPolicy::try_new(class_policies(), specs)
            .unwrap_or_else(|error| panic!("test policy failed: {error}"))
    }

    fn ledger(identity: u8, total: u32, reserved: u32) -> DomainPermitLedger {
        DomainPermitLedger::try_new(
            DomainPermitLedgerId::new([identity; 16], 1),
            total,
            reserved,
        )
        .unwrap_or_else(|error| panic!("test ledger failed: {error}"))
    }

    fn select(
        policy: &mut DispatchPolicy,
        inputs: &[DispatchReadiness],
        ledger: &mut DomainPermitLedger,
    ) -> (super::DispatchSelection, DomainPermitToken) {
        let Ok(decision) = policy.try_select_and_acquire(inputs, ledger) else {
            panic!("test selection must succeed");
        };
        let DispatchDecision::Selected(grant) = decision else {
            panic!("test selection must not be idle");
        };
        grant.into_parts()
    }

    fn release(ledger: &mut DomainPermitLedger, mut permit: DomainPermitToken) {
        if let Err(error) = ledger.release(&mut permit) {
            panic!("test permit release failed: {error}");
        }
        assert!(!permit.is_active());
    }

    const AB_TRACE_TICKS: usize = 32_000;
    const AB_CONTROL_INTERVAL_TICKS: usize = 8;
    const AB_DATA_ARRIVALS_PER_TICK: usize = 2;
    const AB_START_CAPACITY_PER_TICK: usize = 1;
    const AB_STREAM_SLOTS: usize = 4;
    const AB_BACKGROUND_SLOTS: usize = 4;
    const AB_BACKGROUND_START: usize = 1 + AB_STREAM_SLOTS;
    const AB_SLOT_COUNT: usize = 1 + AB_STREAM_SLOTS + AB_BACKGROUND_SLOTS;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct AlgorithmTraceTick {
        control: bool,
        stream_slot: usize,
        background_slot: usize,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct AlgorithmDispatchEvidence {
        control_wait_ticks: Vec<u64>,
        flood_starts_by_slot: Vec<u64>,
        maximum_background_gap_ticks: u64,
        trailing_background_gap_ticks: u64,
    }

    fn two_x_data_overload_trace() -> Vec<AlgorithmTraceTick> {
        (0..AB_TRACE_TICKS)
            .map(|tick| AlgorithmTraceTick {
                control: tick % AB_CONTROL_INTERVAL_TICKS == 0,
                stream_slot: 1 + tick % AB_STREAM_SLOTS,
                background_slot: AB_BACKGROUND_START + tick % AB_BACKGROUND_SLOTS,
            })
            .collect()
    }

    const fn ab_class(index: usize) -> DispatchClass {
        if index == 0 {
            DispatchClass::Control
        } else if index < AB_BACKGROUND_START {
            DispatchClass::Stream
        } else {
            DispatchClass::Background
        }
    }

    /// Flat direct-dispatch reference over the same class-labelled workload.
    /// It intentionally ignores class grouping while retaining exact arrival,
    /// ready-order, cost, capacity, and permit-before-dequeue semantics.
    fn run_flat_direct_dispatch_trace(trace: &[AlgorithmTraceTick]) -> AlgorithmDispatchEvidence {
        let control_arrivals = trace.iter().filter(|tick| tick.control).count();
        let mut queued_at = (0..AB_SLOT_COUNT)
            .map(|_| VecDeque::new())
            .collect::<Vec<VecDeque<u64>>>();
        let mut permits = ledger(0x69, 1, 0);
        let mut cursor = 0_usize;
        let mut control_wait_ticks = Vec::with_capacity(control_arrivals);
        let mut flood_starts_by_slot = vec![0_u64; AB_SLOT_COUNT];
        let mut maximum_background_gap_ticks = 0_u64;
        let mut trailing_background_gap_ticks = 0_u64;
        let maximum_ticks = trace
            .len()
            .checked_add(control_arrivals.saturating_mul(AB_SLOT_COUNT))
            .unwrap_or_else(|| panic!("flat A/B trace bound must fit"));
        let mut tick = 0_usize;

        while tick < trace.len() || control_wait_ticks.len() < control_arrivals {
            assert!(tick < maximum_ticks, "flat A/B control cohort must drain");
            let tick_value =
                u64::try_from(tick).unwrap_or_else(|_| panic!("flat A/B tick must fit in u64"));
            if let Some(arrivals) = trace.get(tick) {
                if arrivals.control {
                    queued_at[0].push_back(tick_value);
                }
                queued_at[arrivals.stream_slot].push_back(tick_value);
                queued_at[arrivals.background_slot].push_back(tick_value);
            }

            let selected = (0..AB_SLOT_COUNT)
                .map(|offset| (cursor + offset) % AB_SLOT_COUNT)
                .find(|index| !queued_at[*index].is_empty())
                .unwrap_or_else(|| panic!("flat A/B dispatch requires one ready mailbox"));
            let permit = permits
                .try_acquire(ab_class(selected))
                .unwrap_or_else(|error| panic!("flat A/B permit failed: {error}"))
                .unwrap_or_else(|| panic!("flat A/B shared permit must be available"));
            let enqueued_at = queued_at[selected]
                .pop_front()
                .unwrap_or_else(|| panic!("flat A/B choice must have a queued item"));
            cursor = (selected + 1) % AB_SLOT_COUNT;
            if selected == 0 {
                control_wait_ticks.push(tick_value - enqueued_at);
            }
            if tick < trace.len() {
                flood_starts_by_slot[selected] += 1;
                if selected >= AB_BACKGROUND_START {
                    maximum_background_gap_ticks =
                        maximum_background_gap_ticks.max(trailing_background_gap_ticks);
                    trailing_background_gap_ticks = 0;
                } else {
                    trailing_background_gap_ticks += 1;
                }
            }
            release(&mut permits, permit);
            tick += 1;
        }

        AlgorithmDispatchEvidence {
            control_wait_ticks,
            flood_starts_by_slot,
            maximum_background_gap_ticks,
            trailing_background_gap_ticks,
        }
    }

    fn run_algorithm_dispatch_trace(
        mut policy: DispatchPolicy,
        expected_path: SelectionPath,
        trace: &[AlgorithmTraceTick],
    ) -> AlgorithmDispatchEvidence {
        let control_arrivals = trace.iter().filter(|tick| tick.control).count();
        let ready = (0..AB_SLOT_COUNT)
            .map(|index| {
                detached_ready(
                    u16::try_from(index + 1)
                        .unwrap_or_else(|_| panic!("A/B mailbox index must fit")),
                )
            })
            .collect::<Vec<_>>();
        let mailboxes = ready.iter().map(|input| input.mailbox).collect::<Vec<_>>();
        let mut queued_at = (0..AB_SLOT_COUNT)
            .map(|_| VecDeque::new())
            .collect::<Vec<VecDeque<u64>>>();
        let mut permits = ledger(0x6a, 1, 0);
        let mut control_wait_ticks = Vec::with_capacity(control_arrivals);
        let mut flood_starts_by_slot = vec![0_u64; AB_SLOT_COUNT];
        let mut maximum_background_gap_ticks = 0_u64;
        let mut trailing_background_gap_ticks = 0_u64;
        let maximum_ticks = trace
            .len()
            .checked_add(control_arrivals.saturating_mul(AB_SLOT_COUNT))
            .unwrap_or_else(|| panic!("A/B trace bound must fit"));
        let mut tick = 0_usize;

        while tick < trace.len() || control_wait_ticks.len() < control_arrivals {
            assert!(tick < maximum_ticks, "A/B control cohort must drain");
            let tick_value =
                u64::try_from(tick).unwrap_or_else(|_| panic!("A/B tick must fit in u64"));
            if let Some(arrivals) = trace.get(tick) {
                if arrivals.control {
                    queued_at[0].push_back(tick_value);
                }
                queued_at[arrivals.stream_slot].push_back(tick_value);
                queued_at[arrivals.background_slot].push_back(tick_value);
            }

            let inputs = queued_at
                .iter()
                .enumerate()
                .filter(|(_, queue)| !queue.is_empty())
                .map(|(index, _)| ready[index])
                .collect::<Vec<_>>();
            let (choice, permit) = select(&mut policy, &inputs, &mut permits);
            assert_eq!(choice.path(), expected_path);
            let selected = mailboxes
                .iter()
                .position(|mailbox| *mailbox == choice.mailbox())
                .unwrap_or_else(|| panic!("A/B choice must name a fixture mailbox"));
            let enqueued_at = queued_at[selected]
                .pop_front()
                .unwrap_or_else(|| panic!("A/B choice must have a queued item"));
            if selected == 0 {
                control_wait_ticks.push(tick_value - enqueued_at);
            }
            if tick < trace.len() {
                flood_starts_by_slot[selected] += 1;
                if selected >= AB_BACKGROUND_START {
                    maximum_background_gap_ticks =
                        maximum_background_gap_ticks.max(trailing_background_gap_ticks);
                    trailing_background_gap_ticks = 0;
                } else {
                    trailing_background_gap_ticks += 1;
                }
            }
            release(&mut permits, permit);
            tick += 1;
        }

        AlgorithmDispatchEvidence {
            control_wait_ticks,
            flood_starts_by_slot,
            maximum_background_gap_ticks,
            trailing_background_gap_ticks,
        }
    }

    fn nearest_rank_percentile(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
        assert!(!samples.is_empty());
        assert!(numerator > 0 && numerator <= denominator);
        let mut ordered = samples.to_vec();
        ordered.sort_unstable();
        let rank = ordered
            .len()
            .checked_mul(numerator)
            .unwrap_or_else(|| panic!("percentile rank must fit"))
            .div_ceil(denominator);
        ordered[rank - 1]
    }

    fn latency_summary(samples: &[u64]) -> [u64; 5] {
        [
            nearest_rank_percentile(samples, 50, 100),
            nearest_rank_percentile(samples, 95, 100),
            nearest_rank_percentile(samples, 99, 100),
            nearest_rank_percentile(samples, 999, 1_000),
            *samples
                .iter()
                .max()
                .unwrap_or_else(|| panic!("latency summary requires samples")),
        ]
    }

    #[test]
    fn fixed_table_rejects_overflow_and_equal_cost_ab_uses_direct_rotation() {
        let too_many = (0..=MAX_DISPATCH_SLOTS)
            .map(|index| {
                slot(
                    u16::try_from(index).unwrap_or(u16::MAX),
                    DispatchClass::Interactive,
                    1,
                    1,
                    1,
                )
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            DispatchPolicy::try_new(class_policies(), too_many),
            Err(DispatcherError::TooManySlots)
        ));

        let mut weighted_policy = policy(vec![
            slot(1, DispatchClass::Interactive, 1, 1, 1),
            slot(2, DispatchClass::Interactive, 1, 1, 1),
        ]);
        assert_eq!(weighted_policy.slot_count(), 2);
        let inputs = [detached_ready(1), detached_ready(2)];
        let mut permits = ledger(1, 1, 0);
        let mut selected = Vec::new();
        for _ in 0..6 {
            let (choice, permit) = select(&mut weighted_policy, &inputs, &mut permits);
            assert_eq!(choice.path(), SelectionPath::DirectScan);
            selected.push(choice.mailbox());
            release(&mut permits, permit);
        }
        assert_eq!(
            selected,
            vec![
                mailbox_ref(1),
                mailbox_ref(2),
                mailbox_ref(1),
                mailbox_ref(2),
                mailbox_ref(1),
                mailbox_ref(2),
            ]
        );
    }

    #[test]
    fn signed_dispatch_scalar_limits_map_without_internal_narrowing() {
        assert!(
            DispatchSlotSpec::try_new(
                mailbox_ref(1),
                DispatchClass::Control,
                MAX_SERVICE_COST_TOKENS,
                MAX_MINIMUM_SERVICE_WEIGHT,
                u16::MAX,
            )
            .is_ok()
        );
        assert!(DispatchClassPolicy::try_new(MAX_CLASS_QUANTUM, MAX_CLASS_BURST).is_ok());
        assert!(matches!(
            DispatchClassPolicy::try_new(MAX_CLASS_QUANTUM + 1, 1),
            Err(DispatcherError::InvalidWeight)
        ));
        assert!(matches!(
            DispatchClassPolicy::try_new(1, MAX_CLASS_BURST + 1),
            Err(DispatcherError::InvalidBurst)
        ));
        assert!(matches!(
            DispatchSlotSpec::try_new(
                mailbox_ref(1),
                DispatchClass::Control,
                MAX_SERVICE_COST_TOKENS + 1,
                1,
                1,
            ),
            Err(DispatcherError::InvalidCost)
        ));
        assert!(matches!(
            DispatchSlotSpec::try_new(
                mailbox_ref(1),
                DispatchClass::Control,
                1,
                MAX_MINIMUM_SERVICE_WEIGHT + 1,
                1,
            ),
            Err(DispatcherError::InvalidWeight)
        ));
        assert!(matches!(
            DispatchSlotSpec::try_new(mailbox_ref(1), DispatchClass::Control, 1, 1, 0),
            Err(DispatcherError::InvalidBurst)
        ));
    }

    #[test]
    fn permit_reserve_conservation_mismatch_and_repeat_release_fail_closed() {
        let mut permits = ledger(1, 3, 1);
        let mut data_one = permits
            .try_acquire(DispatchClass::Interactive)
            .unwrap_or_else(|error| panic!("data permit failed: {error}"))
            .unwrap_or_else(|| panic!("first shared permit must exist"));
        let mut data_two = permits
            .try_acquire(DispatchClass::Background)
            .unwrap_or_else(|error| panic!("data permit failed: {error}"))
            .unwrap_or_else(|| panic!("second shared permit must exist"));
        assert!(matches!(
            permits.try_acquire(DispatchClass::Stream),
            Ok(None)
        ));
        let mut control_reserved = permits
            .try_acquire(DispatchClass::Control)
            .unwrap_or_else(|error| panic!("control permit failed: {error}"))
            .unwrap_or_else(|| panic!("control reserve must exist"));
        let full = permits
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot failed: {error}"));
        assert_eq!(full.total(), 3);
        assert_eq!(full.control_reserved(), 1);
        assert_eq!(full.shared_in_use(), 2);
        assert_eq!(full.control_reserved_in_use(), 1);
        assert_eq!(full.in_use(), 3);
        assert_eq!(full.available(), 0);

        assert!(permits.release(&mut data_one).is_ok());
        let mut control_shared = permits
            .try_acquire(DispatchClass::Control)
            .unwrap_or_else(|error| panic!("shared control permit failed: {error}"))
            .unwrap_or_else(|| panic!("control may use shared capacity"));
        assert!(matches!(
            permits.try_acquire(DispatchClass::Interactive),
            Ok(None)
        ));
        let before_repeat = permits
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot failed: {error}"));
        assert_eq!(
            permits.release(&mut data_one),
            Err(PermitError::AlreadyReleased)
        );
        assert_eq!(
            permits
                .snapshot()
                .unwrap_or_else(|error| panic!("snapshot failed: {error}")),
            before_repeat
        );

        let mut other = ledger(2, 1, 0);
        assert_eq!(
            other.release(&mut data_two),
            Err(PermitError::LedgerMismatch)
        );
        assert!(data_two.is_active());
        assert!(permits.release(&mut data_two).is_ok());
        assert!(permits.release(&mut control_reserved).is_ok());
        assert!(permits.release(&mut control_shared).is_ok());
        assert_eq!(
            permits
                .snapshot()
                .unwrap_or_else(|error| panic!("snapshot failed: {error}"))
                .in_use(),
            0
        );

        let mut same_values_new_ledger = ledger(1, 1, 0);
        let mut same_values_token = permits
            .try_acquire(DispatchClass::Interactive)
            .unwrap_or_else(|error| panic!("same-value source permit failed: {error}"))
            .unwrap_or_else(|| panic!("same-value source permit must exist"));
        assert_eq!(
            same_values_new_ledger.release(&mut same_values_token),
            Err(PermitError::LedgerMismatch)
        );
        assert!(same_values_token.is_active());
        assert!(permits.release(&mut same_values_token).is_ok());

        let mut reverse_token = same_values_new_ledger
            .try_acquire(DispatchClass::Interactive)
            .unwrap_or_else(|error| panic!("same-value reverse permit failed: {error}"))
            .unwrap_or_else(|| panic!("same-value reverse permit must exist"));
        assert_eq!(
            permits.release(&mut reverse_token),
            Err(PermitError::LedgerMismatch)
        );
        assert!(reverse_token.is_active());
        assert!(same_values_new_ledger.release(&mut reverse_token).is_ok());
    }

    #[test]
    fn domain_permit_precedes_dequeue_and_no_permit_preserves_queue() {
        let mut mailbox = mailbox_with_message(1, 100, 100, 100);
        let input = [readiness(&mailbox, 0)];
        let before = mailbox
            .snapshot()
            .unwrap_or_else(|error| panic!("mailbox snapshot failed: {error}"));

        let mut data_policy = policy(vec![slot(1, DispatchClass::Interactive, 1, 1, 1)]);
        let mut permits = ledger(1, 1, 1);
        assert!(matches!(
            data_policy.try_select_and_acquire(&input, &mut permits),
            Ok(DispatchDecision::Idle(DispatchIdleReason::NoDomainPermit))
        ));
        assert_eq!(
            mailbox
                .snapshot()
                .unwrap_or_else(|error| panic!("mailbox snapshot failed: {error}")),
            before
        );

        let mut control_policy = policy(vec![slot(1, DispatchClass::Control, 1, 1, 1)]);
        let (choice, permit) = select(&mut control_policy, &input, &mut permits);
        assert_eq!(choice.mailbox(), mailbox.reference());
        assert_eq!(choice.class(), DispatchClass::Control);
        assert_eq!(choice.cost(), 1);
        assert_eq!(
            mailbox
                .snapshot()
                .unwrap_or_else(|error| panic!("mailbox snapshot failed: {error}")),
            before
        );

        let Ok(report) = mailbox.try_begin_inflight(reading(0)) else {
            panic!("permitted mailbox dequeue must succeed");
        };
        let (outcome, expired) = report.into_parts();
        assert!(expired.is_empty());
        let MailboxDispatchOutcome::Started(token) = outcome else {
            panic!("mailbox must start after domain grant");
        };
        assert!(mailbox.finish(token, TerminalReason::Completed).is_ok());
        release(&mut permits, permit);
        let after = mailbox
            .snapshot()
            .unwrap_or_else(|error| panic!("mailbox snapshot failed: {error}"));
        assert_eq!(after.queued_items(), 0);
        assert_eq!(after.inflight_items(), 0);
        assert_eq!(after.retained_bytes(), 0);
    }

    #[test]
    fn four_class_flood_has_minimum_service_and_bounded_background_gap() {
        let mut policy = policy(vec![
            slot(1, DispatchClass::Control, 1, 1, 4),
            slot(2, DispatchClass::Interactive, 1, 1, 3),
            slot(3, DispatchClass::Stream, 1, 1, 2),
            slot(4, DispatchClass::Background, 1, 1, 1),
        ]);
        let inputs = [
            detached_ready(1),
            detached_ready(2),
            detached_ready(3),
            detached_ready(4),
        ];
        let mut permits = ledger(1, 1, 0);
        let mut counts = [0_u32; 4];
        let mut since_background = 0_u32;
        let mut maximum_background_gap = 0_u32;
        for _ in 0..100 {
            let (choice, permit) = select(&mut policy, &inputs, &mut permits);
            counts[choice.class().index()] += 1;
            if choice.class() == DispatchClass::Background {
                maximum_background_gap = maximum_background_gap.max(since_background);
                since_background = 0;
            } else {
                since_background += 1;
            }
            assert_eq!(choice.path(), SelectionPath::HierarchicalDeficit);
            release(&mut permits, permit);
        }
        assert!(counts.iter().all(|count| *count > 0));
        assert!(counts[0] > counts[1]);
        assert!(counts[1] > counts[2]);
        assert!(counts[2] > counts[3]);
        assert!(maximum_background_gap <= 9);
        assert!(since_background <= 9);
    }

    #[test]
    fn weighted_deficit_accounts_for_large_costs_and_slot_weights() {
        let mut cost_policy = policy(vec![
            slot(1, DispatchClass::Interactive, 1, 1, 8),
            slot(2, DispatchClass::Interactive, 4, 1, 8),
        ]);
        let cost_inputs = [detached_ready(1), detached_ready(2)];
        let mut permits = ledger(1, 1, 0);
        let mut count = [0_u32; 2];
        for _ in 0..100 {
            let (choice, permit) = select(&mut cost_policy, &cost_inputs, &mut permits);
            if choice.mailbox() == mailbox_ref(1) {
                count[0] += 1;
            } else {
                count[1] += 1;
            }
            release(&mut permits, permit);
        }
        let cheap_service = count[0];
        let expensive_service = count[1] * 4;
        assert!(cheap_service.abs_diff(expensive_service) <= 4);
        assert!(count[0] > count[1]);

        let mut weight_policy = policy(vec![
            slot(3, DispatchClass::Stream, 1, 1, 8),
            slot(4, DispatchClass::Stream, 1, 3, 8),
        ]);
        let weight_inputs = [detached_ready(3), detached_ready(4)];
        let mut weighted = [0_u32; 2];
        for _ in 0..80 {
            let (choice, permit) = select(&mut weight_policy, &weight_inputs, &mut permits);
            if choice.mailbox() == mailbox_ref(3) {
                weighted[0] += 1;
            } else {
                weighted[1] += 1;
            }
            release(&mut permits, permit);
        }
        assert!(weighted[0] > 0);
        assert_eq!(weighted[1], weighted[0] * 3);
    }

    #[test]
    fn cross_class_unequal_cost_flood_accounts_tokens_and_bounds_wait() {
        let equal_quantum = [
            class_policy(1, 1),
            class_policy(1, 1),
            class_policy(1, 1),
            class_policy(1, 1),
        ];
        let mut policy = DispatchPolicy::try_new(
            equal_quantum,
            vec![
                slot(1, DispatchClass::Interactive, 100, 1, 1),
                slot(2, DispatchClass::Stream, 1, 1, 1),
            ],
        )
        .unwrap_or_else(|error| panic!("unequal-cost policy failed: {error}"));
        let inputs = [detached_ready(1), detached_ready(2)];
        let mut permits = ledger(1, 1, 0);
        let mut expensive_invocations = 0_u64;
        let mut cheap_invocations = 0_u64;
        let mut cheap_since_expensive = 0_u64;
        let mut maximum_expensive_gap = 0_u64;

        for _ in 0..10_000 {
            let (choice, permit) = select(&mut policy, &inputs, &mut permits);
            if choice.mailbox() == mailbox_ref(1) {
                expensive_invocations += 1;
                maximum_expensive_gap = maximum_expensive_gap.max(cheap_since_expensive);
                cheap_since_expensive = 0;
            } else {
                cheap_invocations += 1;
                cheap_since_expensive += 1;
            }
            release(&mut permits, permit);
        }

        let expensive_tokens = expensive_invocations * 100;
        assert!(expensive_invocations > 0);
        assert!(cheap_invocations > expensive_invocations * 90);
        assert!(expensive_tokens.abs_diff(cheap_invocations) <= 100);
        assert!(maximum_expensive_gap <= 100);
        assert!(cheap_since_expensive <= 100);
    }

    #[test]
    fn sole_expensive_runnable_fast_forwards_and_ignores_exhausted_burst() {
        let unit_quantum = [
            class_policy(1, 1),
            class_policy(1, 1),
            class_policy(1, 1),
            class_policy(1, 1),
        ];
        let mut policy = DispatchPolicy::try_new(
            unit_quantum,
            vec![
                slot(1, DispatchClass::Interactive, MAX_SERVICE_COST_TOKENS, 1, 1),
                slot(2, DispatchClass::Stream, 1, 1, 1),
            ],
        )
        .unwrap_or_else(|error| panic!("expensive policy failed: {error}"));
        let only_ready = [detached_ready(1)];
        let mut permits = ledger(1, 1, 0);

        for _ in 0..3 {
            let (choice, permit) = select(&mut policy, &only_ready, &mut permits);
            assert_eq!(choice.mailbox(), mailbox_ref(1));
            assert_eq!(choice.cost(), MAX_SERVICE_COST_TOKENS);
            assert_eq!(choice.path(), SelectionPath::HierarchicalDeficit);
            release(&mut permits, permit);
        }
    }

    #[test]
    fn deterministic_scheduler_two_x_overload_ab_improves_control_tail_without_starvation() {
        const CONTROL_MINIMUM_BUSINESS_DEADLINE_TICKS: u64 = 9;
        const CONTROL_CALLBACK_BUDGET_TICKS: u64 = 1;
        const CONTROL_START_DEADLINE_TICKS: u64 =
            CONTROL_MINIMUM_BUSINESS_DEADLINE_TICKS - CONTROL_CALLBACK_BUDGET_TICKS;
        const BACKGROUND_MAXIMUM_GAP_TICKS: u64 = 16;
        // Nearest-rank [p50, p95, p99, p99.9, max] over the same 4,000
        // control arrivals. These exact scheduler-tick results make the
        // algorithm-level A/B repeatable without claiming platform latency.
        const EXPECTED_DIRECT_CONTROL_LATENCY: [u64; 5] = [1_999, 3_799, 3_959, 3_995, 3_999];
        const EXPECTED_HIERARCHICAL_CONTROL_LATENCY: [u64; 5] = [1, 2, 2, 2, 2];

        let trace = two_x_data_overload_trace();
        assert_eq!(trace.len(), AB_TRACE_TICKS);
        // Every flood tick offers one stream plus one bulk item against one
        // dispatcher start: data arrival capacity / service capacity = 2 / 1.
        assert_eq!(AB_DATA_ARRIVALS_PER_TICK, AB_START_CAPACITY_PER_TICK * 2);
        assert!(trace.iter().all(|tick| {
            tick.stream_slot < AB_BACKGROUND_START && tick.background_slot >= AB_BACKGROUND_START
        }));

        // The flat baseline and hierarchical run consume the exact same
        // class-labelled arrivals, ready order, unit costs, and one-start per
        // tick capacity. Only class grouping/deficit arbitration differs. The
        // separate equal-scalar test above pins the production DirectScan path
        // to the same flat round-robin rule.
        let direct = run_flat_direct_dispatch_trace(&trace);
        let hierarchical = run_algorithm_dispatch_trace(
            policy(
                (0..AB_SLOT_COUNT)
                    .map(|index| {
                        slot(
                            u16::try_from(index + 1)
                                .unwrap_or_else(|_| panic!("hierarchical slot index must fit")),
                            ab_class(index),
                            1,
                            1,
                            1,
                        )
                    })
                    .collect(),
            ),
            SelectionPath::HierarchicalDeficit,
            &trace,
        );

        let expected_control_samples = AB_TRACE_TICKS / AB_CONTROL_INTERVAL_TICKS;
        assert_eq!(direct.control_wait_ticks.len(), expected_control_samples);
        assert_eq!(
            hierarchical.control_wait_ticks.len(),
            expected_control_samples
        );
        let direct_latency = latency_summary(&direct.control_wait_ticks);
        let hierarchical_latency = latency_summary(&hierarchical.control_wait_ticks);
        let [direct_p50, direct_p95, direct_p99, direct_p999, direct_max] = direct_latency;
        let [
            hierarchical_p50,
            hierarchical_p95,
            hierarchical_p99,
            hierarchical_p999,
            hierarchical_max,
        ] = hierarchical_latency;
        assert_eq!(direct_latency, EXPECTED_DIRECT_CONTROL_LATENCY);
        assert_eq!(hierarchical_latency, EXPECTED_HIERARCHICAL_CONTROL_LATENCY);

        // This is deterministic scheduler-tick evidence, not wall-clock or
        // target-hardware hard-real-time evidence. Its start threshold is
        // derived from the fixture's explicit minimum business deadline minus
        // the callback budget: 9 - 1 = 8 scheduler ticks.
        assert!(
            hierarchical_p99 < CONTROL_START_DEADLINE_TICKS,
            "hierarchical p99={hierarchical_p99}, start deadline={CONTROL_START_DEADLINE_TICKS}, direct p99={direct_p99}"
        );
        assert!(
            hierarchical_p999 < CONTROL_START_DEADLINE_TICKS,
            "hierarchical p99.9={hierarchical_p999}, start deadline={CONTROL_START_DEADLINE_TICKS}, direct p99.9={direct_p999}"
        );
        assert!(
            hierarchical_p99 <= direct_p99 && hierarchical_p999 <= direct_p999,
            "hierarchical p50/p95/p99/p99.9/max={hierarchical_p50}/{hierarchical_p95}/{hierarchical_p99}/{hierarchical_p999}/{hierarchical_max}, direct={direct_p50}/{direct_p95}/{direct_p99}/{direct_p999}/{direct_max}"
        );
        assert!(
            hierarchical_p99 < direct_p99 || hierarchical_p999 < direct_p999,
            "hierarchical tail must strictly improve at least one percentile: hierarchical={hierarchical_p99}/{hierarchical_p999}, direct={direct_p99}/{direct_p999}"
        );
        assert!(
            hierarchical.flood_starts_by_slot[AB_BACKGROUND_START..]
                .iter()
                .all(|starts| *starts > 0),
            "every bulk/background mailbox must receive service: {:?}",
            &hierarchical.flood_starts_by_slot[AB_BACKGROUND_START..]
        );
        assert_eq!(
            &hierarchical.flood_starts_by_slot[AB_BACKGROUND_START..],
            &[2_334, 2_333, 2_333, 2_333]
        );
        assert_eq!(hierarchical.maximum_background_gap_ticks, 3);
        assert_eq!(hierarchical.trailing_background_gap_ticks, 1);
        assert!(
            hierarchical.maximum_background_gap_ticks <= BACKGROUND_MAXIMUM_GAP_TICKS,
            "background max gap={}, bound={BACKGROUND_MAXIMUM_GAP_TICKS}",
            hierarchical.maximum_background_gap_ticks
        );
        assert!(
            hierarchical.trailing_background_gap_ticks <= BACKGROUND_MAXIMUM_GAP_TICKS,
            "background trailing gap={}, bound={BACKGROUND_MAXIMUM_GAP_TICKS}",
            hierarchical.trailing_background_gap_ticks
        );
    }

    #[test]
    fn slot_max_burst_bounds_a_heavy_peer_and_expired_hints_are_idle() {
        let mut burst_policy = policy(vec![
            slot(1, DispatchClass::Stream, 1, 8, 2),
            slot(2, DispatchClass::Stream, 1, 1, 2),
        ]);
        let inputs = [detached_ready(1), detached_ready(2)];
        let mut permits = ledger(1, 1, 0);
        let mut last = None;
        let mut run = 0_u32;
        let mut maximum_heavy_run = 0_u32;
        let mut light_count = 0_u32;
        for _ in 0..60 {
            let (choice, permit) = select(&mut burst_policy, &inputs, &mut permits);
            if last == Some(choice.mailbox()) {
                run += 1;
            } else {
                last = Some(choice.mailbox());
                run = 1;
            }
            if choice.mailbox() == mailbox_ref(1) {
                maximum_heavy_run = maximum_heavy_run.max(run);
            } else {
                light_count += 1;
            }
            release(&mut permits, permit);
        }
        assert!(light_count > 0);
        assert!(maximum_heavy_run <= 2);

        let expired_mailbox = mailbox_with_message(3, 5, 50, 50);
        let expired = readiness(&expired_mailbox, 5);
        assert!(matches!(
            expired.head,
            MailboxHeadReadiness::Expired {
                reason: TerminalReason::StaleBeforeRun,
                ..
            }
        ));
        let before = expired_mailbox
            .snapshot()
            .unwrap_or_else(|error| panic!("mailbox snapshot failed: {error}"));
        let mut expired_policy = policy(vec![slot(3, DispatchClass::Control, 1, 1, 1)]);
        assert!(matches!(
            expired_policy.try_select_and_acquire(&[expired], &mut permits),
            Ok(DispatchDecision::Idle(DispatchIdleReason::NoReadyMailbox))
        ));
        assert_eq!(
            expired_mailbox
                .snapshot()
                .unwrap_or_else(|error| panic!("mailbox snapshot failed: {error}")),
            before
        );
    }
}
