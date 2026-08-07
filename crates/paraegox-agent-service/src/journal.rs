use core::fmt;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::unistd::Uid;
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalV1, MAX_AGENT_CONVERSATION_FRAME_BYTES,
};
use sha2::{Digest, Sha256};

const STORE_RECORDS_DIRECTORY: &str = "records";
const STORE_WRITER_LOCK: &str = ".writer.lock";
const RECORD_MAGIC: &[u8; 4] = b"PXAJ";
const RECORD_VERSION: u16 = 1;
const RECORD_HEADER_BYTES: usize = 64;
const RECORD_RESERVED_BYTES: usize = 7;
const RECORD_CHECKSUM_DOMAIN: &[u8] = b"paraegox.agent.session.journal.record.sha256.v1";
const RECORD_SUFFIX: &str = ".pxaj";
const TEMP_SUFFIX: &str = ".pxaj.tmp";
const SEQUENCE_DIGITS: usize = 20;
const MAX_RECORD_BYTES: usize = RECORD_HEADER_BYTES + MAX_AGENT_CONVERSATION_FRAME_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentSessionJournalError {
    Io(io::ErrorKind),
    LockContended,
    InsecurePermissions,
    UnexpectedStoreEntry,
    TruncatedRecord,
    RecordTooLarge,
    InvalidMagic,
    UnsupportedVersion,
    InvalidHeaderLength,
    InvalidFrameLength,
    UnknownRecordKind,
    ReservedBitsSet,
    ChecksumMismatch,
    SequenceGap,
    DuplicateSequence,
    RecordCapacityExceeded,
    CorruptPayload,
    StateConflict,
    Poisoned,
}

impl fmt::Display for AgentSessionJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(formatter, "AgentSession journal I/O failed: {kind:?}"),
            Self::LockContended => formatter.write_str("AgentSession journal writer lock is held"),
            Self::InsecurePermissions => {
                formatter.write_str("AgentSession journal path is not owner-private")
            }
            Self::UnexpectedStoreEntry => {
                formatter.write_str("AgentSession journal contains an unexpected store entry")
            }
            Self::TruncatedRecord => {
                formatter.write_str("AgentSession journal record is truncated")
            }
            Self::RecordTooLarge => {
                formatter.write_str("AgentSession journal record exceeds its bound")
            }
            Self::InvalidMagic => formatter.write_str("AgentSession journal magic is invalid"),
            Self::UnsupportedVersion => {
                formatter.write_str("AgentSession journal version is unsupported")
            }
            Self::InvalidHeaderLength => {
                formatter.write_str("AgentSession journal header length is invalid")
            }
            Self::InvalidFrameLength => {
                formatter.write_str("AgentSession journal frame length is invalid")
            }
            Self::UnknownRecordKind => {
                formatter.write_str("AgentSession journal record kind is unknown")
            }
            Self::ReservedBitsSet => {
                formatter.write_str("AgentSession journal reserved bytes are nonzero")
            }
            Self::ChecksumMismatch => {
                formatter.write_str("AgentSession journal checksum mismatched")
            }
            Self::SequenceGap => {
                formatter.write_str("AgentSession journal sequence contains a gap")
            }
            Self::DuplicateSequence => {
                formatter.write_str("AgentSession journal sequence is duplicated")
            }
            Self::RecordCapacityExceeded => {
                formatter.write_str("AgentSession journal record capacity is exhausted")
            }
            Self::CorruptPayload => formatter.write_str("AgentSession journal payload is invalid"),
            Self::StateConflict => {
                formatter.write_str("AgentSession journal state transition is invalid")
            }
            Self::Poisoned => formatter.write_str("AgentSession journal requires reopen"),
        }
    }
}

impl std::error::Error for AgentSessionJournalError {}

impl From<io::Error> for AgentSessionJournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JournalEvent {
    SessionOpened {
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
    },
    RequestAccepted(AgentConversationRequestV1),
    TerminalCommitted(AgentConversationTerminalV1),
    CancelIntentRecorded {
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
    },
    ModelHandoffCommitted {
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
    },
    DeckRunSealed(AgentConversationDeckRunId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalRecord {
    pub(crate) sequence: u64,
    pub(crate) event: JournalEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum RecordKind {
    SessionOpened = 1,
    RequestAccepted = 2,
    TerminalCommitted = 3,
    DeckRunSealed = 4,
    CancelIntentRecorded = 5,
    ModelHandoffCommitted = 6,
}

impl RecordKind {
    fn decode(value: u8) -> Result<Self, AgentSessionJournalError> {
        match value {
            1 => Ok(Self::SessionOpened),
            2 => Ok(Self::RequestAccepted),
            3 => Ok(Self::TerminalCommitted),
            4 => Ok(Self::DeckRunSealed),
            5 => Ok(Self::CancelIntentRecorded),
            6 => Ok(Self::ModelHandoffCommitted),
            _ => Err(AgentSessionJournalError::UnknownRecordKind),
        }
    }
}

#[derive(Debug)]
pub(crate) struct DurableAgentSessionJournal {
    _writer_lock: File,
    records_directory: PathBuf,
    next_sequence: u64,
    max_records: usize,
    poisoned: bool,
}

impl DurableAgentSessionJournal {
    pub(crate) fn open(
        root: &Path,
        max_records: usize,
    ) -> Result<(Self, Vec<JournalRecord>), AgentSessionJournalError> {
        if ensure_private_directory(root)? {
            sync_directory(existing_parent(root))?;
        }
        let lock_path = root.join(STORE_WRITER_LOCK);
        reject_symlink(&lock_path)?;
        let writer_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?;
        ensure_private_file(&lock_path)?;
        match writer_lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(AgentSessionJournalError::LockContended);
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }

        let records_directory = root.join(STORE_RECORDS_DIRECTORY);
        if ensure_private_directory(&records_directory)? {
            sync_directory(root)?;
        }
        validate_root_entries(root)?;
        let records = load_records(&records_directory, max_records)?;
        let next_sequence = u64::try_from(records.len())
            .map_err(|_| AgentSessionJournalError::RecordCapacityExceeded)?
            .checked_add(1)
            .ok_or(AgentSessionJournalError::RecordCapacityExceeded)?;
        Ok((
            Self {
                _writer_lock: writer_lock,
                records_directory,
                next_sequence,
                max_records,
                poisoned: false,
            },
            records,
        ))
    }

    pub(crate) fn append(&mut self, event: &JournalEvent) -> Result<u64, AgentSessionJournalError> {
        if self.poisoned {
            return Err(AgentSessionJournalError::Poisoned);
        }
        let result = self.append_inner(event);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn append_inner(&mut self, event: &JournalEvent) -> Result<u64, AgentSessionJournalError> {
        let sequence_index = usize::try_from(self.next_sequence)
            .map_err(|_| AgentSessionJournalError::RecordCapacityExceeded)?;
        if sequence_index == 0 || sequence_index > self.max_records {
            return Err(AgentSessionJournalError::RecordCapacityExceeded);
        }
        let bytes = encode_record(self.next_sequence, event)?;
        let final_path = self
            .records_directory
            .join(canonical_record_name(self.next_sequence));
        let temp_path = self
            .records_directory
            .join(canonical_temp_name(self.next_sequence));
        if final_path.exists() || temp_path.exists() {
            return Err(AgentSessionJournalError::DuplicateSequence);
        }
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        temp.write_all(&bytes)?;
        temp.sync_all()?;
        drop(temp);
        fs::rename(&temp_path, &final_path)?;
        sync_directory(&self.records_directory)?;
        let committed = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(AgentSessionJournalError::RecordCapacityExceeded)?;
        Ok(committed)
    }
}

fn ensure_private_directory(path: &Path) -> Result<bool, AgentSessionJournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_private_directory_metadata(&metadata)?;
            Ok(false)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700).create(path)?;
            let metadata = fs::symlink_metadata(path)?;
            validate_private_directory_metadata(&metadata)?;
            Ok(true)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_private_directory_metadata(
    metadata: &fs::Metadata,
) -> Result<(), AgentSessionJournalError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(AgentSessionJournalError::InsecurePermissions);
    }
    Ok(())
}

fn ensure_private_file(path: &Path) -> Result<(), AgentSessionJournalError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(AgentSessionJournalError::InsecurePermissions);
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), AgentSessionJournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(AgentSessionJournalError::UnexpectedStoreEntry)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_root_entries(root: &Path) -> Result<(), AgentSessionJournalError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        if name != OsStr::new(STORE_WRITER_LOCK) && name != OsStr::new(STORE_RECORDS_DIRECTORY) {
            return Err(AgentSessionJournalError::UnexpectedStoreEntry);
        }
    }
    Ok(())
}

fn load_records(
    records_directory: &Path,
    max_records: usize,
) -> Result<Vec<JournalRecord>, AgentSessionJournalError> {
    let mut committed = Vec::new();
    let mut temporary = Vec::new();
    for entry in fs::read_dir(records_directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(AgentSessionJournalError::UnexpectedStoreEntry);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| AgentSessionJournalError::UnexpectedStoreEntry)?;
        if let Some(sequence) = parse_record_name(&name) {
            committed.push((sequence, entry.path()));
        } else if let Some(sequence) = parse_temp_name(&name) {
            temporary.push((sequence, entry.path()));
        } else {
            return Err(AgentSessionJournalError::UnexpectedStoreEntry);
        }
    }

    committed.sort_by_key(|(sequence, _)| *sequence);
    if committed.len() > max_records {
        return Err(AgentSessionJournalError::RecordCapacityExceeded);
    }
    let mut records = Vec::with_capacity(committed.len());
    let mut expected = 1_u64;
    for (file_sequence, path) in committed {
        if file_sequence < expected {
            return Err(AgentSessionJournalError::DuplicateSequence);
        }
        if file_sequence > expected {
            return Err(AgentSessionJournalError::SequenceGap);
        }
        let record = decode_record_file(&path, file_sequence)?;
        records.push(record);
        expected = expected
            .checked_add(1)
            .ok_or(AgentSessionJournalError::RecordCapacityExceeded)?;
    }
    match temporary.as_slice() {
        [] => {}
        [(sequence, path)] if *sequence == expected && records.len() < max_records => {
            ensure_private_file(path)?;
            fs::remove_file(path)?;
            sync_directory(records_directory)?;
        }
        _ => return Err(AgentSessionJournalError::UnexpectedStoreEntry),
    }
    Ok(records)
}

fn decode_record_file(
    path: &Path,
    file_sequence: u64,
) -> Result<JournalRecord, AgentSessionJournalError> {
    ensure_private_file(path)?;
    let metadata = fs::metadata(path)?;
    let length =
        usize::try_from(metadata.len()).map_err(|_| AgentSessionJournalError::RecordTooLarge)?;
    if length < RECORD_HEADER_BYTES {
        return Err(AgentSessionJournalError::TruncatedRecord);
    }
    if length > MAX_RECORD_BYTES {
        return Err(AgentSessionJournalError::RecordTooLarge);
    }
    let mut bytes = Vec::with_capacity(length);
    File::open(path)?
        .take(u64::try_from(MAX_RECORD_BYTES + 1).expect("record bound fits u64"))
        .read_to_end(&mut bytes)?;
    decode_record(&bytes, file_sequence)
}

fn decode_record(
    bytes: &[u8],
    file_sequence: u64,
) -> Result<JournalRecord, AgentSessionJournalError> {
    if bytes.len() < RECORD_HEADER_BYTES {
        return Err(AgentSessionJournalError::TruncatedRecord);
    }
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(AgentSessionJournalError::RecordTooLarge);
    }
    if &bytes[0..4] != RECORD_MAGIC {
        return Err(AgentSessionJournalError::InvalidMagic);
    }
    if read_u16(bytes, 4) != RECORD_VERSION {
        return Err(AgentSessionJournalError::UnsupportedVersion);
    }
    if usize::from(read_u16(bytes, 6)) != RECORD_HEADER_BYTES {
        return Err(AgentSessionJournalError::InvalidHeaderLength);
    }
    let frame_length = usize::try_from(read_u32(bytes, 8))
        .map_err(|_| AgentSessionJournalError::InvalidFrameLength)?;
    if frame_length != bytes.len() {
        return Err(AgentSessionJournalError::InvalidFrameLength);
    }
    let sequence = read_u64(bytes, 12);
    if sequence < file_sequence {
        return Err(AgentSessionJournalError::DuplicateSequence);
    }
    if sequence > file_sequence {
        return Err(AgentSessionJournalError::SequenceGap);
    }
    let kind = RecordKind::decode(bytes[20])?;
    if bytes[21..21 + RECORD_RESERVED_BYTES]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(AgentSessionJournalError::ReservedBitsSet);
    }
    let payload_length = usize::try_from(read_u32(bytes, 28))
        .map_err(|_| AgentSessionJournalError::InvalidFrameLength)?;
    if RECORD_HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(AgentSessionJournalError::InvalidFrameLength)?
        != bytes.len()
    {
        return Err(AgentSessionJournalError::InvalidFrameLength);
    }
    let checksum = copy_array::<32>(bytes, 32);
    let payload = &bytes[RECORD_HEADER_BYTES..];
    if checksum != record_checksum(sequence, kind, payload) {
        return Err(AgentSessionJournalError::ChecksumMismatch);
    }
    let event = decode_event(kind, payload)?;
    Ok(JournalRecord { sequence, event })
}

fn encode_record(
    sequence: u64,
    event: &JournalEvent,
) -> Result<Box<[u8]>, AgentSessionJournalError> {
    let (kind, payload) = encode_event(event);
    let frame_length = RECORD_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(AgentSessionJournalError::RecordTooLarge)?;
    if frame_length > MAX_RECORD_BYTES {
        return Err(AgentSessionJournalError::RecordTooLarge);
    }
    let mut bytes = Vec::with_capacity(frame_length);
    bytes.extend_from_slice(RECORD_MAGIC);
    bytes.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    bytes.extend_from_slice(
        &u16::try_from(RECORD_HEADER_BYTES)
            .expect("journal header bound fits u16")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(
        &u32::try_from(frame_length)
            .expect("journal frame bound fits u32")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.push(kind as u8);
    bytes.extend_from_slice(&[0; RECORD_RESERVED_BYTES]);
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("journal payload bound fits u32")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&record_checksum(sequence, kind, &payload));
    bytes.extend_from_slice(&payload);
    debug_assert_eq!(bytes.len(), frame_length);
    Ok(bytes.into_boxed_slice())
}

fn encode_event(event: &JournalEvent) -> (RecordKind, Box<[u8]>) {
    match event {
        JournalEvent::SessionOpened {
            deck_run_id,
            session_id,
        } => {
            let mut payload = Vec::with_capacity(32);
            payload.extend_from_slice(deck_run_id.as_bytes());
            payload.extend_from_slice(session_id.as_bytes());
            (RecordKind::SessionOpened, payload.into_boxed_slice())
        }
        JournalEvent::RequestAccepted(request) => {
            (RecordKind::RequestAccepted, request.canonical_wire())
        }
        JournalEvent::TerminalCommitted(terminal) => {
            (RecordKind::TerminalCommitted, terminal.canonical_wire())
        }
        JournalEvent::DeckRunSealed(deck_run_id) => (
            RecordKind::DeckRunSealed,
            Box::<[u8]>::from(deck_run_id.as_bytes().as_slice()),
        ),
        JournalEvent::CancelIntentRecorded {
            deck_run_id,
            session_id,
            request_id,
        } => {
            let mut payload = Vec::with_capacity(48);
            payload.extend_from_slice(deck_run_id.as_bytes());
            payload.extend_from_slice(session_id.as_bytes());
            payload.extend_from_slice(request_id.as_bytes());
            (RecordKind::CancelIntentRecorded, payload.into_boxed_slice())
        }
        JournalEvent::ModelHandoffCommitted {
            deck_run_id,
            session_id,
            request_id,
        } => {
            let mut payload = Vec::with_capacity(48);
            payload.extend_from_slice(deck_run_id.as_bytes());
            payload.extend_from_slice(session_id.as_bytes());
            payload.extend_from_slice(request_id.as_bytes());
            (
                RecordKind::ModelHandoffCommitted,
                payload.into_boxed_slice(),
            )
        }
    }
}

fn decode_event(
    kind: RecordKind,
    payload: &[u8],
) -> Result<JournalEvent, AgentSessionJournalError> {
    match kind {
        RecordKind::SessionOpened if payload.len() == 32 => Ok(JournalEvent::SessionOpened {
            deck_run_id: AgentConversationDeckRunId::try_from_bytes(copy_array(payload, 0))
                .map_err(|_| AgentSessionJournalError::CorruptPayload)?,
            session_id: AgentConversationSessionId::try_from_bytes(copy_array(payload, 16))
                .map_err(|_| AgentSessionJournalError::CorruptPayload)?,
        }),
        RecordKind::RequestAccepted => AgentConversationRequestV1::decode(payload)
            .map(JournalEvent::RequestAccepted)
            .map_err(|_| AgentSessionJournalError::CorruptPayload),
        RecordKind::TerminalCommitted => AgentConversationTerminalV1::decode(payload)
            .map(JournalEvent::TerminalCommitted)
            .map_err(|_| AgentSessionJournalError::CorruptPayload),
        RecordKind::DeckRunSealed if payload.len() == 16 => {
            AgentConversationDeckRunId::try_from_bytes(copy_array(payload, 0))
                .map(JournalEvent::DeckRunSealed)
                .map_err(|_| AgentSessionJournalError::CorruptPayload)
        }
        RecordKind::CancelIntentRecorded if payload.len() == 48 => {
            Ok(JournalEvent::CancelIntentRecorded {
                deck_run_id: AgentConversationDeckRunId::try_from_bytes(copy_array(payload, 0))
                    .map_err(|_| AgentSessionJournalError::CorruptPayload)?,
                session_id: AgentConversationSessionId::try_from_bytes(copy_array(payload, 16))
                    .map_err(|_| AgentSessionJournalError::CorruptPayload)?,
                request_id: AgentConversationRequestId::try_from_bytes(copy_array(payload, 32))
                    .map_err(|_| AgentSessionJournalError::CorruptPayload)?,
            })
        }
        RecordKind::ModelHandoffCommitted if payload.len() == 48 => {
            Ok(JournalEvent::ModelHandoffCommitted {
                deck_run_id: AgentConversationDeckRunId::try_from_bytes(copy_array(payload, 0))
                    .map_err(|_| AgentSessionJournalError::CorruptPayload)?,
                session_id: AgentConversationSessionId::try_from_bytes(copy_array(payload, 16))
                    .map_err(|_| AgentSessionJournalError::CorruptPayload)?,
                request_id: AgentConversationRequestId::try_from_bytes(copy_array(payload, 32))
                    .map_err(|_| AgentSessionJournalError::CorruptPayload)?,
            })
        }
        _ => Err(AgentSessionJournalError::CorruptPayload),
    }
}

fn record_checksum(sequence: u64, kind: RecordKind, payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RECORD_CHECKSUM_DOMAIN);
    digest.update(RECORD_VERSION.to_be_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update([kind as u8]);
    digest.update(
        u32::try_from(payload.len())
            .expect("journal payload bound fits u32")
            .to_be_bytes(),
    );
    digest.update(payload);
    digest.finalize().into()
}

fn canonical_record_name(sequence: u64) -> String {
    format!("{sequence:0SEQUENCE_DIGITS$}{RECORD_SUFFIX}")
}

fn canonical_temp_name(sequence: u64) -> String {
    format!(".{sequence:0SEQUENCE_DIGITS$}{TEMP_SUFFIX}")
}

fn parse_record_name(name: &str) -> Option<u64> {
    if name.len() != SEQUENCE_DIGITS + RECORD_SUFFIX.len() || !name.ends_with(RECORD_SUFFIX) {
        return None;
    }
    parse_sequence_digits(&name[..SEQUENCE_DIGITS])
}

fn parse_temp_name(name: &str) -> Option<u64> {
    if name.len() != 1 + SEQUENCE_DIGITS + TEMP_SUFFIX.len()
        || !name.starts_with('.')
        || !name.ends_with(TEMP_SUFFIX)
    {
        return None;
    }
    parse_sequence_digits(&name[1..1 + SEQUENCE_DIGITS])
}

fn parse_sequence_digits(digits: &str) -> Option<u64> {
    if digits.len() != SEQUENCE_DIGITS || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn sync_directory(path: &Path) -> Result<(), AgentSessionJournalError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn existing_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(copy_array(bytes, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(copy_array(bytes, offset))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(copy_array(bytes, offset))
}

fn copy_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use paraegox_agent_contracts::{
        AgentConversationRequestId, AgentConversationTerminalFailureV1,
        AgentConversationTerminalResultV1, AgentConversationTurnId,
    };

    use super::*;
    use crate::{AgentService, AgentServiceConfigV1};

    static NEXT_STORE: AtomicU64 = AtomicU64::new(1);

    struct TestStore(PathBuf);

    impl TestStore {
        fn new() -> Self {
            let nonce = NEXT_STORE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "paraegox-agent-accepted-crash-{}-{nonce}",
                std::process::id()
            )))
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            if self.0.exists() {
                fs::remove_dir_all(&self.0).expect("remove isolated test journal");
            }
        }
    }

    #[test]
    fn accepted_without_terminal_reopens_as_uncertain_without_provider_call() {
        let store = TestStore::new();
        let config = AgentServiceConfigV1::try_new(4, 4, 4, 16).expect("config");
        let deck_run_id = AgentConversationDeckRunId::try_from_bytes([1; 16]).expect("DeckRun id");
        let session_id = AgentConversationSessionId::try_from_bytes([2; 16]).expect("Session id");
        let request = AgentConversationRequestV1::try_new(
            deck_run_id,
            session_id,
            AgentConversationTurnId::try_from_bytes([3; 16]).expect("Turn id"),
            AgentConversationRequestId::try_from_bytes([4; 16]).expect("Request id"),
            5_000_000_000,
            "accepted before simulated crash",
        )
        .expect("request");
        {
            let (mut journal, records) =
                DurableAgentSessionJournal::open(&store.0, config.max_journal_records())
                    .expect("open raw owner journal");
            assert!(records.is_empty());
            journal
                .append(&JournalEvent::SessionOpened {
                    deck_run_id,
                    session_id,
                })
                .expect("commit SessionOpened");
            journal
                .append(&JournalEvent::RequestAccepted(request.clone()))
                .expect("commit RequestAccepted");
            // Dropping here models process loss after acceptance and before any
            // provider invocation or terminal commit.
        }

        let service =
            AgentService::open_durable(config, &store.0).expect("recover pending request");
        let terminal = service
            .terminal(deck_run_id, session_id, request.request_id())
            .expect("terminal query")
            .expect("uncertain terminal");
        assert_eq!(
            terminal.result(),
            &AgentConversationTerminalResultV1::Failure(
                AgentConversationTerminalFailureV1::ModelOutcomeUncertain
            )
        );
        assert_eq!(
            fs::read_dir(store.0.join(STORE_RECORDS_DIRECTORY))
                .expect("record directory")
                .count(),
            3
        );
        drop(service);

        let _reopened =
            AgentService::open_durable(config, &store.0).expect("reopen resolved request");
        assert_eq!(
            fs::read_dir(store.0.join(STORE_RECORDS_DIRECTORY))
                .expect("record directory")
                .count(),
            3
        );
    }

    #[test]
    fn cancel_intent_without_handoff_reopens_as_cancelled_before_model() {
        let store = TestStore::new();
        let config = AgentServiceConfigV1::try_new(4, 4, 4, 16).expect("config");
        let deck_run_id = AgentConversationDeckRunId::try_from_bytes([1; 16]).expect("DeckRun id");
        let session_id = AgentConversationSessionId::try_from_bytes([2; 16]).expect("Session id");
        let request = AgentConversationRequestV1::try_new(
            deck_run_id,
            session_id,
            AgentConversationTurnId::try_from_bytes([3; 16]).expect("Turn id"),
            AgentConversationRequestId::try_from_bytes([4; 16]).expect("Request id"),
            5_000_000_000,
            "cancel intent before simulated crash",
        )
        .expect("request");
        {
            let (mut journal, records) =
                DurableAgentSessionJournal::open(&store.0, config.max_journal_records())
                    .expect("open raw owner journal");
            assert!(records.is_empty());
            journal
                .append(&JournalEvent::SessionOpened {
                    deck_run_id,
                    session_id,
                })
                .expect("commit SessionOpened");
            journal
                .append(&JournalEvent::RequestAccepted(request.clone()))
                .expect("commit RequestAccepted");
            journal
                .append(&JournalEvent::CancelIntentRecorded {
                    deck_run_id,
                    session_id,
                    request_id: request.request_id(),
                })
                .expect("commit cancel intent");
            // The absence of the durable handoff marker proves that the model
            // provider never owned this request.
        }

        let service =
            AgentService::open_durable(config, &store.0).expect("recover pending cancellation");
        let snapshot = service
            .export_session_snapshot(deck_run_id, session_id)
            .expect("snapshot");
        assert!(snapshot.requests()[0].cancel_requested());
        assert_eq!(
            snapshot.requests()[0]
                .terminal()
                .expect("cancelled terminal")
                .result(),
            &AgentConversationTerminalResultV1::Failure(
                AgentConversationTerminalFailureV1::CancelledBeforeModel
            )
        );
        assert_eq!(
            fs::read_dir(store.0.join(STORE_RECORDS_DIRECTORY))
                .expect("record directory")
                .count(),
            4
        );
    }

    #[test]
    fn cancel_intent_after_handoff_reopens_as_uncertain() {
        let store = TestStore::new();
        let config = AgentServiceConfigV1::try_new(4, 4, 4, 16).expect("config");
        let deck_run_id = AgentConversationDeckRunId::try_from_bytes([1; 16]).expect("DeckRun id");
        let session_id = AgentConversationSessionId::try_from_bytes([2; 16]).expect("Session id");
        let request = AgentConversationRequestV1::try_new(
            deck_run_id,
            session_id,
            AgentConversationTurnId::try_from_bytes([3; 16]).expect("Turn id"),
            AgentConversationRequestId::try_from_bytes([4; 16]).expect("Request id"),
            5_000_000_000,
            "cancel intent after durable handoff",
        )
        .expect("request");
        {
            let (mut journal, records) =
                DurableAgentSessionJournal::open(&store.0, config.max_journal_records())
                    .expect("open raw owner journal");
            assert!(records.is_empty());
            journal
                .append(&JournalEvent::SessionOpened {
                    deck_run_id,
                    session_id,
                })
                .expect("commit SessionOpened");
            journal
                .append(&JournalEvent::RequestAccepted(request.clone()))
                .expect("commit RequestAccepted");
            journal
                .append(&JournalEvent::ModelHandoffCommitted {
                    deck_run_id,
                    session_id,
                    request_id: request.request_id(),
                })
                .expect("commit model handoff");
            journal
                .append(&JournalEvent::CancelIntentRecorded {
                    deck_run_id,
                    session_id,
                    request_id: request.request_id(),
                })
                .expect("commit cancel intent");
        }

        let service =
            AgentService::open_durable(config, &store.0).expect("recover handed-off cancellation");
        let snapshot = service
            .export_session_snapshot(deck_run_id, session_id)
            .expect("snapshot");
        assert!(snapshot.requests()[0].cancel_requested());
        assert!(snapshot.requests()[0].model_handoff_committed());
        assert_eq!(
            snapshot.requests()[0]
                .terminal()
                .expect("uncertain terminal")
                .result(),
            &AgentConversationTerminalResultV1::Failure(
                AgentConversationTerminalFailureV1::ModelOutcomeUncertain
            )
        );
        assert_eq!(
            fs::read_dir(store.0.join(STORE_RECORDS_DIRECTORY))
                .expect("record directory")
                .count(),
            5
        );
    }
}
