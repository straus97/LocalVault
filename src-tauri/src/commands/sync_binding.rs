//! Tauri command boundary over the session-owned sync-binding workflow
//! (Stage 1U-4 B1j-1).
//!
//! **These commands are deliberately not registered in `generate_handler!`**, so
//! the frontend cannot reach them. B1j-2 registers them together with the UI.
//!
//! The module is a thin shell. Every rule (one-time consumption, the 120-second
//! lifetime, stale-preview detection, repeat file validation, Core
//! authentication, physical-alias rejection, no-clobber creation, fresh-load
//! verification, evidence-bound conditional deletion) lives in the session
//! methods that [`AppState`] already exposes; nothing here repeats or relaxes
//! one. What this module adds:
//!
//! * fixed, serializable shapes (DTOs) that carry only what a person needs to
//!   see, and a redacted `Debug` for every one that holds a path or an id;
//! * a fixed, sanitized [`CommandError`] for every outcome;
//! * the Rust-owned native file picker, and the check that the session a
//!   selection is prepared for is the session that opened the picker.
//!
//! # File selection
//!
//! The frontend never supplies a target path. `choose_and_prepare_sync_binding`
//! opens the native picker from Rust, filtered to `*.lvault`, with the
//! application-state mutex **not** held. The chosen path is only a candidate: it
//! goes through the unchanged B1h preparation (which validates and reads the
//! file) and nothing is bound until a separate `confirm_sync_binding` call with
//! the preparation id. A selection alone is never consent.
//!
//! # Session identity across the picker
//!
//! The picker can stay open while the vault locks, expires or is replaced. The
//! command takes a [`SessionToken`](crate::app_state::SessionToken) before the
//! picker opens and the preparation re-checks it under the state mutex, so a path
//! chosen for one session can never be prepared for another.
//!
//! Errors and `Debug` output never carry a path, password, key, fingerprint,
//! salt, physical file identifier, raw store error or preparation id.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use serde::Serialize;
use tauri::{AppHandle, State, WebviewWindow};
use tauri_plugin_dialog::{DialogExt, FilePath};

use super::CommandError;
use crate::{
    app_state::{AppState, AppStateError, SessionToken},
    vault::{
        session::{
            BindingAttention, BindingResetConfirmRefusal, BindingResetConsequence,
            BindingResetPreview, BindingResetRefusal, BindingResetStale, BindingResetSubject,
            BindingState, BindingStatus, InitialBindingConfirmRefusal, InitialBindingPreview,
            InitialBindingRefusal, InitialBindingStale, PendingPushIndication,
            SyncStateUnavailable,
        },
        sync_file_adapter::{SyncFileTarget, UnavailableReason},
        sync_state_store::SyncStateRoot,
    },
};

// -- Error codes ------------------------------------------------------------
//
// Fixed codes and messages. A message never names a path, an id or a value, and
// never claims that anything was synchronized, uploaded or enabled.

const fn error(code: &'static str, message: &'static str) -> CommandError {
    CommandError::new(code, message)
}

const FILE_DIALOG_CANCELLED: CommandError = error(
    "syncFileDialogCancelled",
    "No file was selected. Nothing was changed.",
);

const FILE_DIALOG_BUSY: CommandError = error(
    "syncFileDialogBusy",
    "A file selection is already in progress.",
);

const SESSION_CHANGED: CommandError = error(
    "syncSessionChanged",
    "The vault session changed during the file selection. Start again.",
);

const TARGET_INVALID: CommandError = error(
    "syncTargetInvalid",
    "The selected item is not a usable LocalVault file.",
);

const PREPARATION_MISSING: CommandError = error(
    "syncPreparationMissing",
    "There is nothing waiting for confirmation. Start again.",
);

const PREPARATION_STALE: CommandError = error(
    "syncPreparationStale",
    "The confirmation is out of date. Start again.",
);

const TARGET_ABSENT: CommandError = error("syncTargetAbsent", "The selected file was not found.");

const TARGET_UNAVAILABLE: CommandError = error(
    "syncTargetUnavailable",
    "The selected file could not be read.",
);

const TARGET_DIFFERS: CommandError = error(
    "syncTargetDiffers",
    "The selected file is not an identical copy of this vault, or it changed since it was reviewed.",
);

const TARGET_IS_VAULT: CommandError = error(
    "syncTargetIsVault",
    "The selected file is this vault's own file or one of its companion files.",
);

const FILESYSTEM_UNSUPPORTED: CommandError = error(
    "syncFilesystemUnsupported",
    "The selected file's location is not supported or could not be verified.",
);

const LOCAL_VAULT_CHANGED: CommandError = error(
    "syncLocalVaultChanged",
    "The vault file changed on disk. Start again.",
);

const BINDING_EXISTS: CommandError = error(
    "syncBindingExists",
    "A synchronization binding record already exists for this vault.",
);

const BINDING_STATE_CORRUPT: CommandError = error(
    "syncBindingStateCorrupt",
    "The stored synchronization binding record is unreadable or unsupported.",
);

const BINDING_FAILED: CommandError = error(
    "syncBindingFailed",
    "The synchronization binding was not created.",
);

const BINDING_AMBIGUOUS: CommandError = error(
    "syncBindingAmbiguous",
    "The binding could not be verified after writing. Check its status before trying again.",
);

const NOTHING_TO_RESET: CommandError = error(
    "syncNothingToReset",
    "There is no synchronization binding record to reset.",
);

const RESET_EVIDENCE_CHANGED: CommandError = error(
    "syncResetEvidenceChanged",
    "The stored synchronization state changed after it was reviewed. Nothing was removed.",
);

const RESET_NOT_PERMITTED: CommandError = error(
    "syncResetNotPermitted",
    "The stored synchronization state cannot be safely reset.",
);

const RESET_FAILED: CommandError = error(
    "syncResetFailed",
    "The synchronization binding was not reset.",
);

const RESET_AMBIGUOUS: CommandError = error(
    "syncResetAmbiguous",
    "The reset could not be confirmed. Check the binding status before trying again.",
);

// -- Error mapping ----------------------------------------------------------

/// The outer ("no live session") error of an application-state call.
fn app_error(error: AppStateError) -> CommandError {
    match error {
        AppStateError::SessionChanged => SESSION_CHANGED,
        other => CommandError::from(other),
    }
}

fn unavailable_error(reason: SyncStateUnavailable, otherwise: CommandError) -> CommandError {
    match reason {
        SyncStateUnavailable::LocalVaultChanged => LOCAL_VAULT_CHANGED,
        SyncStateUnavailable::LocalLocator | SyncStateUnavailable::Root => otherwise,
    }
}

/// Refusals of both the preparation and the guarded binding it ends in. Every
/// variant except `PersistenceUnverified` is a definite "nothing was created".
fn initial_binding_error(refusal: InitialBindingRefusal) -> CommandError {
    use InitialBindingRefusal as Refusal;

    match refusal {
        Refusal::Unavailable(reason) => unavailable_error(reason, BINDING_FAILED),
        Refusal::ApprovalTargetMismatch | Refusal::Randomness | Refusal::NotPersisted(_) => {
            BINDING_FAILED
        }
        Refusal::ExistingBinding
        | Refusal::ExistingBindingMismatch(_)
        | Refusal::RecordAppeared => BINDING_EXISTS,
        Refusal::Corrupt(_) | Refusal::UnsupportedVersion | Refusal::Unreadable(_) => {
            BINDING_STATE_CORRUPT
        }
        Refusal::TargetIsVaultFile => TARGET_IS_VAULT,
        Refusal::TargetIdentityUncertain => FILESYSTEM_UNSUPPORTED,
        Refusal::TargetAbsentOnDisk => TARGET_ABSENT,
        Refusal::TargetUnavailable(UnavailableReason::Unsupported) => FILESYSTEM_UNSUPPORTED,
        Refusal::TargetUnavailable(_) => TARGET_UNAVAILABLE,
        Refusal::EvidenceChanged => PREPARATION_STALE,
        Refusal::Inspection(_) | Refusal::Transition(_) => TARGET_DIFFERS,
        Refusal::PersistenceUnverified => BINDING_AMBIGUOUS,
    }
}

fn initial_binding_confirm_error(refusal: InitialBindingConfirmRefusal) -> CommandError {
    match refusal {
        InitialBindingConfirmRefusal::Stale(stale) => match stale {
            InitialBindingStale::NoPendingApproval => PREPARATION_MISSING,
            InitialBindingStale::NotCurrentPreparation | InitialBindingStale::Expired => {
                PREPARATION_STALE
            }
            InitialBindingStale::LocalVaultChanged => LOCAL_VAULT_CHANGED,
            InitialBindingStale::TargetChanged => TARGET_DIFFERS,
        },
        InitialBindingConfirmRefusal::Binding(refusal) => initial_binding_error(refusal),
    }
}

/// Reset refusals, at preparation and at confirmation. All are definite: nothing
/// was removed.
fn reset_error(refusal: BindingResetRefusal) -> CommandError {
    match refusal {
        BindingResetRefusal::Unavailable(reason) => unavailable_error(reason, RESET_FAILED),
        BindingResetRefusal::NothingToReset => NOTHING_TO_RESET,
        BindingResetRefusal::UnreadableState(_) | BindingResetRefusal::Evidence(_) => {
            RESET_NOT_PERMITTED
        }
        BindingResetRefusal::RecordChanged => RESET_EVIDENCE_CHANGED,
        BindingResetRefusal::Randomness => RESET_FAILED,
    }
}

fn reset_confirm_error(refusal: BindingResetConfirmRefusal) -> CommandError {
    match refusal {
        BindingResetConfirmRefusal::Stale(stale) => match stale {
            BindingResetStale::NoPendingReset => PREPARATION_MISSING,
            BindingResetStale::NotCurrentPreparation | BindingResetStale::Expired => {
                PREPARATION_STALE
            }
            BindingResetStale::LocatorChanged => LOCAL_VAULT_CHANGED,
            BindingResetStale::RecordChanged => RESET_EVIDENCE_CHANGED,
        },
        BindingResetConfirmRefusal::Refused(refusal) => reset_error(refusal),
        BindingResetConfirmRefusal::NotRemoved(_) => RESET_FAILED,
        BindingResetConfirmRefusal::Ambiguous(_) => RESET_AMBIGUOUS,
    }
}

// -- DTOs -------------------------------------------------------------------

/// Whether a push is recorded as started and not resolved. Says nothing about
/// the target, and is `Unavailable` (not "none") without a verified record.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PendingPushDto {
    None,
    Pending,
    Unavailable,
}

impl From<PendingPushIndication> for PendingPushDto {
    fn from(indication: PendingPushIndication) -> Self {
        match indication {
            PendingPushIndication::None => Self::None,
            PendingPushIndication::Pending => Self::Pending,
            PendingPushIndication::Unavailable => Self::Unavailable,
        }
    }
}

/// Why a stored binding is not shown as linked. One fixed category each; no
/// reason code, I/O kind or stored value.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SyncBindingProblemDto {
    Corrupt,
    UnsupportedVersion,
    Unreadable,
    Mismatch,
    Unavailable,
}

impl From<&BindingAttention> for SyncBindingProblemDto {
    fn from(attention: &BindingAttention) -> Self {
        match attention {
            BindingAttention::Corrupt(_) => Self::Corrupt,
            BindingAttention::UnsupportedVersion => Self::UnsupportedVersion,
            BindingAttention::Unreadable(_) => Self::Unreadable,
            BindingAttention::Mismatch(_) => Self::Mismatch,
            BindingAttention::Unavailable(_) => Self::Unavailable,
        }
    }
}

/// `linked` is the only variant that can carry a path, and only the one the
/// backend authenticated for this vault and location. `needsAttention` has no
/// field that could hold a target.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SyncBindingStateDto {
    NotConfigured,
    #[serde(rename_all = "camelCase")]
    Linked {
        target_path: String,
    },
    NeedsAttention {
        problem: SyncBindingProblemDto,
    },
}

impl std::fmt::Debug for SyncBindingStateDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("NotConfigured"),
            Self::Linked { .. } => f.write_str("Linked(<redacted>)"),
            Self::NeedsAttention { problem } => write!(f, "NeedsAttention({problem:?})"),
        }
    }
}

impl From<&BindingState> for SyncBindingStateDto {
    fn from(state: &BindingState) -> Self {
        match state {
            BindingState::NotConfigured => Self::NotConfigured,
            BindingState::Linked(target) => Self::Linked {
                target_path: target.path().to_owned(),
            },
            BindingState::NeedsAttention(attention) => Self::NeedsAttention {
                problem: attention.into(),
            },
        }
    }
}

/// A local record's state. Not a claim that anything is synchronized.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncBindingStatusDto {
    pub state: SyncBindingStateDto,
    pub pending_push: PendingPushDto,
}

impl From<&BindingStatus> for SyncBindingStatusDto {
    fn from(status: &BindingStatus) -> Self {
        Self {
            state: status.state().into(),
            pending_push: status.pending_push().into(),
        }
    }
}

/// What the person must be shown before confirming an initial binding.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncBindingPreparationDto {
    pub preparation_id: String,
    pub vault_file_name: String,
    pub target_path: String,
}

impl std::fmt::Debug for SyncBindingPreparationDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncBindingPreparationDto(<redacted>)")
    }
}

impl From<&InitialBindingPreview> for SyncBindingPreparationDto {
    fn from(preview: &InitialBindingPreview) -> Self {
        Self {
            preparation_id: preview.preparation_id().to_owned(),
            vault_file_name: preview.vault_file_name().to_owned(),
            target_path: preview.target_path().to_owned(),
        }
    }
}

/// Fieldless on purpose. It means the local record was published and verified by
/// a fresh load; it does not mean anything was synchronized.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SyncBindingOutcomeDto {
    BoundAndVerified,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SyncBindingResetSubjectDto {
    VerifiedBinding,
    MismatchedRecord,
    CorruptRecord,
    UnsupportedRecord,
    InterruptedWriteRemnants,
}

impl From<BindingResetSubject> for SyncBindingResetSubjectDto {
    fn from(subject: BindingResetSubject) -> Self {
        match subject {
            BindingResetSubject::VerifiedBinding => Self::VerifiedBinding,
            BindingResetSubject::MismatchedRecord => Self::MismatchedRecord,
            BindingResetSubject::CorruptRecord => Self::CorruptRecord,
            BindingResetSubject::UnsupportedRecord => Self::UnsupportedRecord,
            BindingResetSubject::InterruptedWriteRemnants => Self::InterruptedWriteRemnants,
        }
    }
}

/// The session's fixed list of facts about a reset, one for one.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SyncBindingResetConsequenceDto {
    RemovesLocalBindingRecord,
    RemovesTrustedSyncHistory,
    MayDiscardPendingSyncIntent,
    KeepsVaultAndBackup,
    KeepsRemoteTarget,
    DoesNotProveRemoteContentAbsent,
    DoesNotEnablePublication,
}

impl From<BindingResetConsequence> for SyncBindingResetConsequenceDto {
    fn from(consequence: BindingResetConsequence) -> Self {
        match consequence {
            BindingResetConsequence::RemovesLocalBindingRecord => Self::RemovesLocalBindingRecord,
            BindingResetConsequence::RemovesTrustedSyncHistory => Self::RemovesTrustedSyncHistory,
            BindingResetConsequence::MayDiscardPendingSyncIntent => {
                Self::MayDiscardPendingSyncIntent
            }
            BindingResetConsequence::KeepsVaultAndBackup => Self::KeepsVaultAndBackup,
            BindingResetConsequence::KeepsRemoteTarget => Self::KeepsRemoteTarget,
            BindingResetConsequence::DoesNotProveRemoteContentAbsent => {
                Self::DoesNotProveRemoteContentAbsent
            }
            BindingResetConsequence::DoesNotEnablePublication => Self::DoesNotEnablePublication,
        }
    }
}

/// Files a reset never touches: it removes only the device-local sync-state
/// record and its recovery artifacts. The same list for every subject.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SyncBindingUntouchedDto {
    PrimaryVault,
    VaultBackup,
    VaultLockFile,
    SelectedTargetFile,
}

const RESET_LEAVES_UNTOUCHED: [SyncBindingUntouchedDto; 4] = [
    SyncBindingUntouchedDto::PrimaryVault,
    SyncBindingUntouchedDto::VaultBackup,
    SyncBindingUntouchedDto::VaultLockFile,
    SyncBindingUntouchedDto::SelectedTargetFile,
];

/// What the person must be shown before confirming a reset. `target_path` is set
/// only for a verified binding.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncBindingResetPreparationDto {
    pub preparation_id: String,
    pub subject: SyncBindingResetSubjectDto,
    pub target_path: Option<String>,
    pub pending_push: PendingPushDto,
    pub consequences: Vec<SyncBindingResetConsequenceDto>,
    pub untouched: Vec<SyncBindingUntouchedDto>,
}

impl std::fmt::Debug for SyncBindingResetPreparationDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncBindingResetPreparationDto(<redacted>)")
    }
}

impl From<&BindingResetPreview> for SyncBindingResetPreparationDto {
    fn from(preview: &BindingResetPreview) -> Self {
        Self {
            preparation_id: preview.preparation_id().to_owned(),
            subject: preview.subject().into(),
            target_path: preview.target_path().map(str::to_owned),
            pending_push: preview.pending_push().into(),
            consequences: preview
                .consequences()
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
            untouched: RESET_LEAVES_UNTOUCHED.to_vec(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SyncBindingResetOutcomeDto {
    ResetAndVerified,
}

// -- File selection ---------------------------------------------------------

/// What the native picker produced, before any validation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Selection {
    /// The user dismissed the picker.
    Cancelled,
    Chosen(PathBuf),
    /// A selection that is not a local file path (for example a URL).
    Unusable,
}

fn classify_selection(picked: Option<FilePath>) -> Selection {
    match picked {
        None => Selection::Cancelled,
        Some(file) => match file.into_path() {
            Ok(path) => Selection::Chosen(path),
            Err(_) => Selection::Unusable,
        },
    }
}

/// The picker's filter is a hint the user can override; this is the check.
fn has_vault_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lvault"))
}

/// Opens the native picker. Blocks until the user answers, so it must run off
/// the main thread (the commands that call it are `async`) and with no lock held.
fn pick_vault_file(app: &AppHandle, window: &WebviewWindow) -> Selection {
    classify_selection(
        app.dialog()
            .file()
            .set_title("Select an existing LocalVault file")
            .add_filter("LocalVault vault", &["lvault"])
            .set_parent(window)
            .blocking_pick_file(),
    )
}

/// At most one picker at a time, released on every path out.
static PICKER_OPEN: AtomicBool = AtomicBool::new(false);

struct PickerSlot;

impl PickerSlot {
    fn acquire() -> Option<Self> {
        PICKER_OPEN
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(Self)
    }
}

impl Drop for PickerSlot {
    fn drop(&mut self) {
        PICKER_OPEN.store(false, Ordering::Release);
    }
}

// -- Testable operations ----------------------------------------------------
//
// The commands below only resolve the trusted root and the picker; everything
// else is here, free of Tauri, so it can be exercised against a real
// `AppState`.

fn status_in(state: &AppState, root: &SyncStateRoot) -> Result<SyncBindingStatusDto, CommandError> {
    state
        .binding_status(root)
        .map(|status| SyncBindingStatusDto::from(&status))
        .map_err(app_error)
}

/// Void older approval, take the session identity, run `pick` with no lock held,
/// then prepare the chosen file for that same session only.
fn choose_and_prepare_in(
    state: &AppState,
    root: &SyncStateRoot,
    pick: impl FnOnce() -> Selection,
) -> Result<SyncBindingPreparationDto, CommandError> {
    let token = state.begin_sync_binding_selection().map_err(app_error)?;

    let abandon = |token: SessionToken| {
        // Idempotent and best effort: the older approval was already voided when
        // the selection began; this only closes the window in between.
        let _ = state.cancel_initial_binding_for_session(token);
    };

    let path = match pick() {
        Selection::Chosen(path) => path,
        Selection::Cancelled => {
            abandon(token);
            return Err(FILE_DIALOG_CANCELLED);
        }
        Selection::Unusable => {
            abandon(token);
            return Err(TARGET_INVALID);
        }
    };

    let target = if has_vault_extension(&path) {
        SyncFileTarget::from_path(&path).ok()
    } else {
        None
    };

    let Some(target) = target else {
        abandon(token);
        return Err(TARGET_INVALID);
    };

    match state.prepare_initial_binding_for_session(token, root, &target) {
        Err(error) => Err(app_error(error)),
        Ok(Err(refusal)) => Err(initial_binding_error(refusal)),
        Ok(Ok(preview)) => Ok(SyncBindingPreparationDto::from(&preview)),
    }
}

fn confirm_in(
    state: &AppState,
    root: &SyncStateRoot,
    preparation_id: &str,
) -> Result<SyncBindingOutcomeDto, CommandError> {
    match state.confirm_initial_binding(root, preparation_id) {
        Err(error) => Err(app_error(error)),
        Ok(Err(refusal)) => Err(initial_binding_confirm_error(refusal)),
        Ok(Ok(_)) => Ok(SyncBindingOutcomeDto::BoundAndVerified),
    }
}

fn prepare_reset_in(
    state: &AppState,
    root: &SyncStateRoot,
) -> Result<SyncBindingResetPreparationDto, CommandError> {
    match state.prepare_binding_reset(root) {
        Err(error) => Err(app_error(error)),
        Ok(Err(refusal)) => Err(reset_error(refusal)),
        Ok(Ok(preview)) => Ok(SyncBindingResetPreparationDto::from(&preview)),
    }
}

fn confirm_reset_in(
    state: &AppState,
    root: &SyncStateRoot,
    preparation_id: &str,
) -> Result<SyncBindingResetOutcomeDto, CommandError> {
    match state.confirm_binding_reset(root, preparation_id) {
        Err(error) => Err(app_error(error)),
        Ok(Err(refusal)) => Err(reset_confirm_error(refusal)),
        Ok(Ok(_)) => Ok(SyncBindingResetOutcomeDto::ResetAndVerified),
    }
}

fn trusted_root(app: &AppHandle, otherwise: CommandError) -> Result<SyncStateRoot, CommandError> {
    SyncStateRoot::from_app(app).map_err(|_| otherwise)
}

// -- Commands (not registered) ----------------------------------------------

/// Read-only status of the local binding record. No remote read or write, and
/// not user activity.
#[tauri::command(async)]
pub fn get_sync_binding_status(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<SyncBindingStatusDto, CommandError> {
    let root = trusted_root(&app, BINDING_FAILED)?;

    status_in(&state, &root)
}

/// Open the native picker for an existing `*.lvault` file and prepare it. Binds
/// nothing: the selection is not consent.
#[tauri::command(async)]
pub fn choose_and_prepare_sync_binding(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<SyncBindingPreparationDto, CommandError> {
    let root = trusted_root(&app, BINDING_FAILED)?;

    let _slot = PickerSlot::acquire().ok_or(FILE_DIALOG_BUSY)?;

    choose_and_prepare_in(&state, &root, || pick_vault_file(&app, &window))
}

#[tauri::command(async)]
pub fn confirm_sync_binding(
    app: AppHandle,
    state: State<'_, AppState>,
    preparation_id: String,
) -> Result<SyncBindingOutcomeDto, CommandError> {
    let root = trusted_root(&app, BINDING_FAILED)?;

    confirm_in(&state, &root, &preparation_id)
}

#[tauri::command]
pub fn cancel_sync_binding(state: State<'_, AppState>) -> Result<(), CommandError> {
    state.cancel_initial_binding().map_err(app_error)
}

#[tauri::command(async)]
pub fn prepare_sync_binding_reset(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<SyncBindingResetPreparationDto, CommandError> {
    let root = trusted_root(&app, RESET_FAILED)?;

    prepare_reset_in(&state, &root)
}

#[tauri::command(async)]
pub fn confirm_sync_binding_reset(
    app: AppHandle,
    state: State<'_, AppState>,
    preparation_id: String,
) -> Result<SyncBindingResetOutcomeDto, CommandError> {
    let root = trusted_root(&app, RESET_FAILED)?;

    confirm_reset_in(&state, &root, &preparation_id)
}

#[tauri::command]
pub fn cancel_sync_binding_reset(state: State<'_, AppState>) -> Result<(), CommandError> {
    state.cancel_binding_reset().map_err(app_error)
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use localvault_core::{
        sync::{BoundInspectionError, EnvelopeInput},
        sync_state::{BindingMismatch, TransitionRefusal},
    };
    use zeroize::Zeroizing;

    use super::*;
    use crate::vault::{
        session::BindingResetAmbiguity,
        sync_state_store::{
            CorruptReason, EvidenceRefusal, StoreError, UnreadableReason, SYNC_STATE_DIRECTORY,
        },
    };

    // Pure mapping tests come first; the flow tests below run the real session
    // and store against scratch under the git-ignored
    // `.qa-local/sync-state-b1-tests/` (never `%TEMP%`). Nothing here opens a
    // native dialog: the picker is exercised only through its result type, and
    // the UI is not tested.

    const PASSWORD: &str = "sync-binding-command-test-only-password";

    const SOME_ID: &str = "00000000-0000-4000-8000-000000000000";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(PASSWORD.to_owned())
    }

    fn qa_scratch(name: &str) -> tempfile::TempDir {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("sync-state-b1-tests");

        fs::create_dir_all(&base).unwrap();

        tempfile::Builder::new()
            .prefix(&format!("{name}-"))
            .tempdir_in(&base)
            .unwrap()
    }

    struct Fixture {
        _scratch: tempfile::TempDir,
        state: AppState,
        root: SyncStateRoot,
        app_local: PathBuf,
        vault: PathBuf,
        remote: PathBuf,
    }

    /// An unlocked vault with no binding and a byte-identical copy as the target.
    fn fixture(name: &str) -> Fixture {
        let scratch = qa_scratch(name);
        let vaults = scratch.path().join("vaults");
        let remote_dir = scratch.path().join("remote");

        fs::create_dir_all(&vaults).unwrap();
        fs::create_dir_all(&remote_dir).unwrap();

        let vault = vaults.join("vault.lvault");
        let remote = remote_dir.join("target.lvault");
        let app_local = scratch.path().join("app-local");

        let state = AppState::default();

        state.create_vault(vault.clone(), password()).unwrap();
        state.lock_vault().unwrap();

        fs::copy(&vault, &remote).unwrap();

        state.unlock_vault(vault.clone(), password()).unwrap();

        Fixture {
            root: SyncStateRoot::for_test(app_local.clone()),
            _scratch: scratch,
            state,
            app_local,
            vault,
            remote,
        }
    }

    impl Fixture {
        fn choose(&self, path: &Path) -> Result<SyncBindingPreparationDto, CommandError> {
            choose_and_prepare_in(&self.state, &self.root, || {
                Selection::Chosen(path.to_owned())
            })
        }

        fn prepare(&self) -> SyncBindingPreparationDto {
            self.choose(&self.remote).unwrap()
        }

        fn bind(&self) {
            let preparation = self.prepare();

            assert_eq!(
                confirm_in(&self.state, &self.root, &preparation.preparation_id),
                Ok(SyncBindingOutcomeDto::BoundAndVerified)
            );
        }

        fn status(&self) -> SyncBindingStatusDto {
            status_in(&self.state, &self.root).unwrap()
        }

        fn record_files(&self) -> Vec<PathBuf> {
            let directory = self.app_local.join(SYNC_STATE_DIRECTORY);

            fs::read_dir(directory)
                .map(|entries| {
                    entries
                        .map(|entry| entry.unwrap().path())
                        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                        .collect()
                })
                .unwrap_or_default()
        }

        fn corrupt_record(&self) {
            let files = self.record_files();

            assert_eq!(files.len(), 1);

            fs::write(&files[0], b"not a sync-state record").unwrap();
        }

        fn relock_and_unlock(&self) {
            self.state.lock_vault().unwrap();
            self.state
                .unlock_vault(self.vault.clone(), password())
                .unwrap();
        }
    }

    fn json<T: Serialize>(value: &T) -> String {
        serde_json::to_string(value).unwrap()
    }

    fn sorted_keys<T: Serialize>(value: &T) -> Vec<String> {
        let value = serde_json::to_value(value).unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();

        keys.sort();

        keys
    }

    // -- status DTO ---------------------------------------------------------

    #[test]
    fn pending_push_indication_maps_one_for_one() {
        assert_eq!(
            PendingPushDto::from(PendingPushIndication::None),
            PendingPushDto::None
        );
        assert_eq!(
            PendingPushDto::from(PendingPushIndication::Pending),
            PendingPushDto::Pending
        );
        assert_eq!(
            PendingPushDto::from(PendingPushIndication::Unavailable),
            PendingPushDto::Unavailable
        );

        assert_eq!(json(&PendingPushDto::None), "\"none\"");
        assert_eq!(json(&PendingPushDto::Pending), "\"pending\"");
        assert_eq!(json(&PendingPushDto::Unavailable), "\"unavailable\"");
    }

    #[test]
    fn needs_attention_maps_to_a_fixed_category_without_a_target() {
        let cases = [
            (
                BindingAttention::Corrupt(CorruptReason::Empty),
                SyncBindingProblemDto::Corrupt,
                "corrupt",
            ),
            (
                BindingAttention::UnsupportedVersion,
                SyncBindingProblemDto::UnsupportedVersion,
                "unsupportedVersion",
            ),
            (
                BindingAttention::Unreadable(UnreadableReason::UnresolvedArtifacts),
                SyncBindingProblemDto::Unreadable,
                "unreadable",
            ),
            (
                BindingAttention::Mismatch(BindingMismatch::TargetLocator),
                SyncBindingProblemDto::Mismatch,
                "mismatch",
            ),
            (
                BindingAttention::Unavailable(SyncStateUnavailable::Root),
                SyncBindingProblemDto::Unavailable,
                "unavailable",
            ),
        ];

        for (attention, problem, name) in cases {
            let dto = SyncBindingStateDto::from(&BindingState::NeedsAttention(attention));

            assert_eq!(dto, SyncBindingStateDto::NeedsAttention { problem });

            assert_eq!(
                json(&dto),
                format!("{{\"kind\":\"needsAttention\",\"problem\":\"{name}\"}}")
            );
        }

        assert_eq!(
            json(&SyncBindingStateDto::from(&BindingState::NotConfigured)),
            "{\"kind\":\"notConfigured\"}"
        );
    }

    #[test]
    fn status_reports_not_configured_then_the_authenticated_target() {
        let f = fixture("b1j1-status-linked");

        assert_eq!(
            f.status(),
            SyncBindingStatusDto {
                state: SyncBindingStateDto::NotConfigured,
                pending_push: PendingPushDto::None,
            }
        );

        f.bind();

        let status = f.status();

        assert_eq!(
            status.state,
            SyncBindingStateDto::Linked {
                target_path: f.remote.to_str().unwrap().to_owned()
            }
        );
        assert_eq!(status.pending_push, PendingPushDto::None);

        let text = json(&status);

        assert!(text.contains("\"kind\":\"linked\""));
        assert!(text.contains("\"targetPath\""));
        assert!(text.contains("\"pendingPush\":\"none\""));

        // Nothing in the vocabulary claims that data moved.
        for word in ["synced", "uploaded", "cloud", "enabled"] {
            assert!(!text.to_lowercase().contains(word));
        }
    }

    #[test]
    fn an_unverifiable_record_never_exposes_its_target() {
        let f = fixture("b1j1-status-corrupt");

        f.bind();
        f.corrupt_record();

        let status = f.status();

        assert_eq!(
            status,
            SyncBindingStatusDto {
                state: SyncBindingStateDto::NeedsAttention {
                    problem: SyncBindingProblemDto::Corrupt
                },
                pending_push: PendingPushDto::Unavailable,
            }
        );

        for text in [json(&status), format!("{status:?}")] {
            assert!(!text.contains("target.lvault"));
            assert!(!text.to_lowercase().contains("targetpath"));
        }
    }

    #[test]
    fn status_requires_a_live_session() {
        let f = fixture("b1j1-status-locked");

        f.state.lock_vault().unwrap();

        assert_eq!(
            status_in(&f.state, &f.root),
            Err(CommandError::from(AppStateError::VaultLocked))
        );
    }

    // -- selection policy ---------------------------------------------------

    #[test]
    fn a_picker_result_is_classified_before_any_validation() {
        assert_eq!(classify_selection(None), Selection::Cancelled);

        let path = PathBuf::from(r"C:\sync\target.lvault");

        assert_eq!(
            classify_selection(Some(FilePath::Path(path.clone()))),
            Selection::Chosen(path)
        );

        let web = url::Url::parse("https://example.invalid/target.lvault").unwrap();

        assert_eq!(
            classify_selection(Some(FilePath::Url(web))),
            Selection::Unusable
        );
    }

    #[test]
    fn only_lvault_files_pass_the_extension_check() {
        assert!(has_vault_extension(Path::new(r"C:\a\vault.lvault")));
        assert!(has_vault_extension(Path::new(r"C:\a\vault.LVAULT")));

        assert!(!has_vault_extension(Path::new(r"C:\a\vault.lvault.bak")));
        assert!(!has_vault_extension(Path::new(r"C:\a\vault.txt")));
        assert!(!has_vault_extension(Path::new(r"C:\a\lvault")));
        assert!(!has_vault_extension(Path::new(r"C:\a\.lvault")));
        assert!(!has_vault_extension(Path::new(r"C:\a\")));
    }

    #[test]
    fn a_cancelled_selection_is_not_consent_and_voids_an_older_approval() {
        let f = fixture("b1j1-cancel");

        let older = f.prepare();

        let result = choose_and_prepare_in(&f.state, &f.root, || Selection::Cancelled);

        assert_eq!(result, Err(FILE_DIALOG_CANCELLED));

        assert_eq!(
            confirm_in(&f.state, &f.root, &older.preparation_id),
            Err(PREPARATION_MISSING)
        );

        assert_eq!(f.status().state, SyncBindingStateDto::NotConfigured);
        assert!(f.record_files().is_empty());
    }

    #[test]
    fn an_invalid_selection_voids_an_older_approval_and_prepares_nothing() {
        let f = fixture("b1j1-invalid");

        let wrong_extension = f.remote.with_extension("txt");

        fs::copy(&f.remote, &wrong_extension).unwrap();

        for selection in [
            Selection::Unusable,
            Selection::Chosen(wrong_extension.clone()),
            Selection::Chosen(PathBuf::from("relative.lvault")),
        ] {
            let older = f.prepare();

            assert_eq!(
                choose_and_prepare_in(&f.state, &f.root, || selection),
                Err(TARGET_INVALID)
            );

            assert_eq!(
                confirm_in(&f.state, &f.root, &older.preparation_id),
                Err(PREPARATION_MISSING)
            );
        }

        assert!(f.record_files().is_empty());
    }

    #[test]
    fn a_refused_target_voids_an_older_approval() {
        let f = fixture("b1j1-refused");

        let older = f.prepare();

        let absent = f.remote.with_file_name("absent.lvault");

        assert_eq!(f.choose(&absent), Err(TARGET_ABSENT));

        assert_eq!(
            confirm_in(&f.state, &f.root, &older.preparation_id),
            Err(PREPARATION_MISSING)
        );

        assert!(!absent.exists(), "nothing is ever created");
    }

    #[test]
    fn the_vault_itself_and_a_different_file_are_refused() {
        let f = fixture("b1j1-vault-or-differs");

        assert_eq!(f.choose(&f.vault), Err(TARGET_IS_VAULT));

        fs::write(&f.remote, b"not an envelope").unwrap();

        assert_eq!(f.choose(&f.remote), Err(TARGET_DIFFERS));

        assert!(f.record_files().is_empty());
    }

    #[test]
    fn the_picker_runs_without_the_state_mutex() {
        let f = fixture("b1j1-no-mutex");

        // Locking needs the state mutex. Were it held across the picker this
        // would deadlock instead of failing.
        let result = choose_and_prepare_in(&f.state, &f.root, || {
            f.state.lock_vault().unwrap();

            Selection::Chosen(f.remote.clone())
        });

        assert_eq!(result, Err(CommandError::from(AppStateError::VaultLocked)));
    }

    // -- session switch -----------------------------------------------------

    #[test]
    fn a_session_replaced_during_the_picker_prepares_nothing() {
        let f = fixture("b1j1-session-switch");

        // The same vault, locked and unlocked again: a different session.
        let result = choose_and_prepare_in(&f.state, &f.root, || {
            f.relock_and_unlock();

            Selection::Chosen(f.remote.clone())
        });

        assert_eq!(result, Err(SESSION_CHANGED));

        // Nothing is pending in the new session either.
        assert_eq!(
            confirm_in(&f.state, &f.root, SOME_ID),
            Err(PREPARATION_MISSING)
        );

        assert_eq!(f.status().state, SyncBindingStateDto::NotConfigured);
        assert!(f.record_files().is_empty());
    }

    #[test]
    fn a_session_locked_during_the_picker_fails_closed() {
        let f = fixture("b1j1-session-locked");

        let result = choose_and_prepare_in(&f.state, &f.root, || {
            f.state.lock_vault().unwrap();

            Selection::Chosen(f.remote.clone())
        });

        assert_eq!(result, Err(CommandError::from(AppStateError::VaultLocked)));

        f.state.unlock_vault(f.vault.clone(), password()).unwrap();

        assert_eq!(
            confirm_in(&f.state, &f.root, SOME_ID),
            Err(PREPARATION_MISSING)
        );
    }

    #[test]
    fn an_old_selection_ending_leaves_the_new_sessions_approval_alone() {
        let f = fixture("b1j1-cancel-after-switch");

        let mut new_session_id = String::new();

        let result = choose_and_prepare_in(&f.state, &f.root, || {
            f.relock_and_unlock();

            // The new session prepares its own approval while the old picker is
            // still open; the old selection ending must not discard it.
            new_session_id = f.prepare().preparation_id;

            Selection::Cancelled
        });

        assert_eq!(result, Err(FILE_DIALOG_CANCELLED));

        assert_eq!(
            confirm_in(&f.state, &f.root, &new_session_id),
            Ok(SyncBindingOutcomeDto::BoundAndVerified)
        );
    }

    #[test]
    fn a_selection_cannot_start_without_a_live_session() {
        let f = fixture("b1j1-selection-locked");

        f.state.lock_vault().unwrap();

        let mut opened = false;

        let result = choose_and_prepare_in(&f.state, &f.root, || {
            opened = true;

            Selection::Cancelled
        });

        assert_eq!(result, Err(CommandError::from(AppStateError::VaultLocked)));
        assert!(!opened, "the picker must not open for a locked vault");
    }

    #[test]
    fn only_one_picker_can_be_open() {
        let first = PickerSlot::acquire().expect("the slot starts free");

        assert!(PickerSlot::acquire().is_none());

        drop(first);

        assert!(PickerSlot::acquire().is_some());
    }

    // -- initial binding flow -----------------------------------------------

    #[test]
    fn preparation_returns_only_the_reviewed_values() {
        let f = fixture("b1j1-prepare");

        let preparation = f.prepare();

        assert_eq!(preparation.vault_file_name, "vault.lvault");
        assert_eq!(preparation.target_path, f.remote.to_str().unwrap());
        assert!(!preparation.preparation_id.is_empty());

        assert_eq!(
            sorted_keys(&preparation),
            ["preparationId", "targetPath", "vaultFileName"]
        );

        // Preparing binds nothing.
        assert_eq!(f.status().state, SyncBindingStateDto::NotConfigured);
        assert!(f.record_files().is_empty());
    }

    #[test]
    fn confirmation_resolves_the_target_from_the_session_and_spends_the_preparation() {
        let f = fixture("b1j1-confirm");

        let preparation = f.prepare();

        assert_eq!(
            confirm_in(&f.state, &f.root, &preparation.preparation_id),
            Ok(SyncBindingOutcomeDto::BoundAndVerified)
        );

        assert_eq!(
            json(&SyncBindingOutcomeDto::BoundAndVerified),
            "\"boundAndVerified\""
        );

        assert!(matches!(
            f.status().state,
            SyncBindingStateDto::Linked { .. }
        ));

        // Spent: a second confirmation, a replay, binds nothing.
        assert_eq!(
            confirm_in(&f.state, &f.root, &preparation.preparation_id),
            Err(PREPARATION_MISSING)
        );
    }

    #[test]
    fn a_wrong_id_is_stale_and_spends_the_preparation() {
        let f = fixture("b1j1-confirm-wrong-id");

        for wrong in [SOME_ID, "not-an-id", ""] {
            let current = f.prepare();

            assert_eq!(
                confirm_in(&f.state, &f.root, wrong),
                Err(PREPARATION_STALE),
                "{wrong:?}"
            );

            assert_eq!(
                confirm_in(&f.state, &f.root, &current.preparation_id),
                Err(PREPARATION_MISSING)
            );
        }

        assert!(f.record_files().is_empty());
    }

    #[test]
    fn cancelling_discards_the_preparation_and_is_idempotent() {
        let f = fixture("b1j1-cancel-binding");

        let preparation = f.prepare();

        f.state.cancel_initial_binding().unwrap();
        f.state.cancel_initial_binding().unwrap();

        assert_eq!(
            confirm_in(&f.state, &f.root, &preparation.preparation_id),
            Err(PREPARATION_MISSING)
        );
    }

    #[test]
    fn a_changed_target_is_refused_at_confirmation() {
        let f = fixture("b1j1-target-changed");

        let preparation = f.prepare();

        let mut bytes = fs::read(&f.remote).unwrap();

        bytes.push(b' ');

        fs::write(&f.remote, bytes).unwrap();

        assert_eq!(
            confirm_in(&f.state, &f.root, &preparation.preparation_id),
            Err(TARGET_DIFFERS)
        );
        assert!(f.record_files().is_empty());
    }

    #[test]
    fn an_existing_binding_is_not_replaced() {
        let f = fixture("b1j1-existing");

        f.bind();

        assert_eq!(f.choose(&f.remote), Err(BINDING_EXISTS));
    }

    #[test]
    fn confirmation_requires_a_live_session() {
        let f = fixture("b1j1-confirm-locked");

        let preparation = f.prepare();

        f.state.lock_vault().unwrap();

        assert_eq!(
            confirm_in(&f.state, &f.root, &preparation.preparation_id),
            Err(CommandError::from(AppStateError::VaultLocked))
        );

        // The preparation died with the session.
        f.state.unlock_vault(f.vault.clone(), password()).unwrap();

        assert_eq!(
            confirm_in(&f.state, &f.root, &preparation.preparation_id),
            Err(PREPARATION_MISSING)
        );
    }

    // -- reset flow ---------------------------------------------------------

    #[test]
    fn a_verified_binding_resets_through_prepare_and_confirm() {
        let f = fixture("b1j1-reset");

        f.bind();

        let preparation = prepare_reset_in(&f.state, &f.root).unwrap();

        assert_eq!(
            preparation.subject,
            SyncBindingResetSubjectDto::VerifiedBinding
        );
        assert_eq!(
            preparation.target_path.as_deref(),
            Some(f.remote.to_str().unwrap())
        );
        assert_eq!(preparation.pending_push, PendingPushDto::None);

        use SyncBindingResetConsequenceDto as C;

        assert_eq!(
            preparation.consequences,
            [
                C::RemovesLocalBindingRecord,
                C::RemovesTrustedSyncHistory,
                C::MayDiscardPendingSyncIntent,
                C::KeepsVaultAndBackup,
                C::KeepsRemoteTarget,
                C::DoesNotProveRemoteContentAbsent,
                C::DoesNotEnablePublication,
            ]
        );

        assert_eq!(
            preparation.untouched,
            [
                SyncBindingUntouchedDto::PrimaryVault,
                SyncBindingUntouchedDto::VaultBackup,
                SyncBindingUntouchedDto::VaultLockFile,
                SyncBindingUntouchedDto::SelectedTargetFile,
            ]
        );

        // Preparing removes nothing.
        assert_eq!(f.record_files().len(), 1);

        assert_eq!(
            confirm_reset_in(&f.state, &f.root, &preparation.preparation_id),
            Ok(SyncBindingResetOutcomeDto::ResetAndVerified)
        );

        assert!(f.record_files().is_empty());
        assert!(f.remote.exists(), "the target is never deleted");
        assert!(f.vault.exists(), "the vault is never deleted");
        assert_eq!(f.status().state, SyncBindingStateDto::NotConfigured);

        assert_eq!(
            confirm_reset_in(&f.state, &f.root, &preparation.preparation_id),
            Err(PREPARATION_MISSING)
        );
        assert_eq!(prepare_reset_in(&f.state, &f.root), Err(NOTHING_TO_RESET));
    }

    #[test]
    fn the_reset_preview_shape_is_fixed() {
        let f = fixture("b1j1-reset-shape");

        f.bind();

        let preparation = prepare_reset_in(&f.state, &f.root).unwrap();

        assert_eq!(
            sorted_keys(&preparation),
            [
                "consequences",
                "pendingPush",
                "preparationId",
                "subject",
                "targetPath",
                "untouched"
            ]
        );

        let value = serde_json::to_value(&preparation).unwrap();

        assert_eq!(value["subject"], "verifiedBinding");
        assert_eq!(value["consequences"][1], "removesTrustedSyncHistory");
        assert_eq!(value["consequences"][2], "mayDiscardPendingSyncIntent");
        assert_eq!(value["untouched"][2], "vaultLockFile");
    }

    #[test]
    fn an_unverified_record_resets_without_exposing_a_target() {
        let f = fixture("b1j1-reset-corrupt");

        f.bind();
        f.corrupt_record();

        let preparation = prepare_reset_in(&f.state, &f.root).unwrap();

        assert_eq!(
            preparation.subject,
            SyncBindingResetSubjectDto::CorruptRecord
        );
        assert_eq!(preparation.target_path, None);
        assert_eq!(preparation.pending_push, PendingPushDto::Unavailable);

        assert!(!json(&preparation).contains("target.lvault"));

        assert_eq!(
            confirm_reset_in(&f.state, &f.root, &preparation.preparation_id),
            Ok(SyncBindingResetOutcomeDto::ResetAndVerified)
        );
    }

    #[test]
    fn a_reset_confirmation_is_one_time_and_cancellable() {
        let f = fixture("b1j1-reset-stale");

        f.bind();

        let first = prepare_reset_in(&f.state, &f.root).unwrap();

        assert_eq!(
            confirm_reset_in(&f.state, &f.root, SOME_ID),
            Err(PREPARATION_STALE)
        );

        // Spent by the wrong-id attempt.
        assert_eq!(
            confirm_reset_in(&f.state, &f.root, &first.preparation_id),
            Err(PREPARATION_MISSING)
        );

        let second = prepare_reset_in(&f.state, &f.root).unwrap();

        f.state.cancel_binding_reset().unwrap();
        f.state.cancel_binding_reset().unwrap();

        assert_eq!(
            confirm_reset_in(&f.state, &f.root, &second.preparation_id),
            Err(PREPARATION_MISSING)
        );

        assert_eq!(f.record_files().len(), 1, "nothing was removed");
    }

    #[test]
    fn a_changed_record_is_not_removed_by_an_old_reset_preview() {
        let f = fixture("b1j1-reset-changed");

        f.bind();

        let preparation = prepare_reset_in(&f.state, &f.root).unwrap();

        f.corrupt_record();

        assert_eq!(
            confirm_reset_in(&f.state, &f.root, &preparation.preparation_id),
            Err(RESET_EVIDENCE_CHANGED)
        );
        assert_eq!(f.record_files().len(), 1);
    }

    #[test]
    fn a_reset_attempt_voids_a_pending_binding_approval() {
        let f = fixture("b1j1-exclusive");

        let binding = f.prepare();

        // Nothing is bound, so the reset is refused, but the attempt still
        // voids the approval.
        assert_eq!(prepare_reset_in(&f.state, &f.root), Err(NOTHING_TO_RESET));

        assert_eq!(
            confirm_in(&f.state, &f.root, &binding.preparation_id),
            Err(PREPARATION_MISSING)
        );
    }

    #[test]
    fn reset_requires_a_live_session() {
        let f = fixture("b1j1-reset-locked");

        f.state.lock_vault().unwrap();

        let locked = CommandError::from(AppStateError::VaultLocked);

        assert_eq!(prepare_reset_in(&f.state, &f.root), Err(locked.clone()));
        assert_eq!(confirm_reset_in(&f.state, &f.root, SOME_ID), Err(locked));

        // Cancelling is not an error, with or without a session.
        assert!(f.state.cancel_binding_reset().is_ok());
        assert!(f.state.cancel_initial_binding().is_ok());
    }

    // -- error mapping ------------------------------------------------------

    const ALL_ERRORS: [CommandError; 21] = [
        FILE_DIALOG_CANCELLED,
        FILE_DIALOG_BUSY,
        SESSION_CHANGED,
        TARGET_INVALID,
        PREPARATION_MISSING,
        PREPARATION_STALE,
        TARGET_ABSENT,
        TARGET_UNAVAILABLE,
        TARGET_DIFFERS,
        TARGET_IS_VAULT,
        FILESYSTEM_UNSUPPORTED,
        LOCAL_VAULT_CHANGED,
        BINDING_EXISTS,
        BINDING_STATE_CORRUPT,
        BINDING_FAILED,
        BINDING_AMBIGUOUS,
        NOTHING_TO_RESET,
        RESET_EVIDENCE_CHANGED,
        RESET_NOT_PERMITTED,
        RESET_FAILED,
        RESET_AMBIGUOUS,
    ];

    #[test]
    fn error_codes_are_unique_fixed_and_free_of_dynamic_content() {
        let mut codes: Vec<_> = ALL_ERRORS.iter().map(|e| e.code).collect();

        codes.sort_unstable();

        let before = codes.len();

        codes.dedup();

        assert_eq!(codes.len(), before, "codes must be unique");

        for error in ALL_ERRORS {
            assert!(error.code.starts_with("sync"));
            assert!(error.message.ends_with('.'));

            let message = error.message.to_lowercase();

            for forbidden in ["synced", "uploaded", "cloud", "enabled", "\\", "/", ":"] {
                assert!(!message.contains(forbidden), "{}: {forbidden}", error.code);
            }
        }
    }

    #[test]
    fn outer_session_errors_reuse_the_established_codes() {
        assert_eq!(app_error(AppStateError::VaultLocked).code, "vaultLocked");
        assert_eq!(
            app_error(AppStateError::SessionExpired).code,
            "vaultSessionExpired"
        );
        assert_eq!(
            app_error(AppStateError::StateUnavailable).code,
            "stateUnavailable"
        );
        assert_eq!(app_error(AppStateError::SessionChanged), SESSION_CHANGED);
    }

    #[test]
    fn initial_binding_refusals_map_to_fixed_codes() {
        use InitialBindingRefusal as R;

        let malformed = BoundInspectionError::MalformedEnvelope {
            input: EnvelopeInput::Candidate,
        };

        let cases: Vec<(R, CommandError)> = vec![
            (
                R::Unavailable(SyncStateUnavailable::LocalLocator),
                BINDING_FAILED,
            ),
            (R::Unavailable(SyncStateUnavailable::Root), BINDING_FAILED),
            (
                R::Unavailable(SyncStateUnavailable::LocalVaultChanged),
                LOCAL_VAULT_CHANGED,
            ),
            (R::ApprovalTargetMismatch, BINDING_FAILED),
            (R::ExistingBinding, BINDING_EXISTS),
            (
                R::ExistingBindingMismatch(BindingMismatch::VaultIdentity),
                BINDING_EXISTS,
            ),
            (
                R::Corrupt(CorruptReason::Undecodable),
                BINDING_STATE_CORRUPT,
            ),
            (R::UnsupportedVersion, BINDING_STATE_CORRUPT),
            (
                R::Unreadable(UnreadableReason::Io(io::ErrorKind::PermissionDenied)),
                BINDING_STATE_CORRUPT,
            ),
            (R::TargetIsVaultFile, TARGET_IS_VAULT),
            (R::TargetIdentityUncertain, FILESYSTEM_UNSUPPORTED),
            (R::TargetAbsentOnDisk, TARGET_ABSENT),
            (
                R::TargetUnavailable(UnavailableReason::Unsupported),
                FILESYSTEM_UNSUPPORTED,
            ),
            (
                R::TargetUnavailable(UnavailableReason::Io(io::ErrorKind::NotFound)),
                TARGET_UNAVAILABLE,
            ),
            (
                R::TargetUnavailable(UnavailableReason::ParentMissing),
                TARGET_UNAVAILABLE,
            ),
            (R::EvidenceChanged, PREPARATION_STALE),
            (R::Inspection(malformed), TARGET_DIFFERS),
            (R::Randomness, BINDING_FAILED),
            (
                R::Transition(TransitionRefusal::RemoteDiffers),
                TARGET_DIFFERS,
            ),
            (
                R::Transition(TransitionRefusal::LocalUnversioned),
                TARGET_DIFFERS,
            ),
            (R::RecordAppeared, BINDING_EXISTS),
            (R::NotPersisted(StoreError::AlreadyExists), BINDING_FAILED),
            (R::PersistenceUnverified, BINDING_AMBIGUOUS),
        ];

        for (refusal, expected) in cases {
            assert_eq!(initial_binding_error(refusal), expected, "{refusal:?}");

            // Only an unverified write is ambiguous; every other refusal is a
            // definite "nothing was created".
            assert_eq!(
                expected == BINDING_AMBIGUOUS,
                refusal == R::PersistenceUnverified
            );
        }
    }

    #[test]
    fn initial_binding_confirm_refusals_map_to_fixed_codes() {
        use InitialBindingConfirmRefusal as C;
        use InitialBindingStale as S;

        let cases = [
            (C::Stale(S::NoPendingApproval), PREPARATION_MISSING),
            (C::Stale(S::NotCurrentPreparation), PREPARATION_STALE),
            (C::Stale(S::Expired), PREPARATION_STALE),
            (C::Stale(S::LocalVaultChanged), LOCAL_VAULT_CHANGED),
            (C::Stale(S::TargetChanged), TARGET_DIFFERS),
            (
                C::Binding(InitialBindingRefusal::PersistenceUnverified),
                BINDING_AMBIGUOUS,
            ),
            (
                C::Binding(InitialBindingRefusal::ExistingBinding),
                BINDING_EXISTS,
            ),
        ];

        for (refusal, expected) in cases {
            assert_eq!(
                initial_binding_confirm_error(refusal),
                expected,
                "{refusal:?}"
            );
        }
    }

    #[test]
    fn reset_refusals_map_to_fixed_codes() {
        use BindingResetRefusal as R;

        let cases = [
            (R::Unavailable(SyncStateUnavailable::Root), RESET_FAILED),
            (
                R::Unavailable(SyncStateUnavailable::LocalLocator),
                RESET_FAILED,
            ),
            (
                R::Unavailable(SyncStateUnavailable::LocalVaultChanged),
                LOCAL_VAULT_CHANGED,
            ),
            (R::NothingToReset, NOTHING_TO_RESET),
            (
                R::UnreadableState(UnreadableReason::UnexpectedObject),
                RESET_NOT_PERMITTED,
            ),
            (R::Evidence(EvidenceRefusal::Oversized), RESET_NOT_PERMITTED),
            (R::RecordChanged, RESET_EVIDENCE_CHANGED),
            (R::Randomness, RESET_FAILED),
        ];

        for (refusal, expected) in cases {
            assert_eq!(reset_error(refusal), expected, "{refusal:?}");
        }
    }

    #[test]
    fn reset_confirmation_outcomes_separate_definite_failure_from_ambiguity() {
        use BindingResetConfirmRefusal as C;
        use BindingResetStale as S;

        let cases = [
            (C::Stale(S::NoPendingReset), PREPARATION_MISSING),
            (C::Stale(S::NotCurrentPreparation), PREPARATION_STALE),
            (C::Stale(S::Expired), PREPARATION_STALE),
            (C::Stale(S::LocatorChanged), LOCAL_VAULT_CHANGED),
            (C::Stale(S::RecordChanged), RESET_EVIDENCE_CHANGED),
            (
                C::Refused(BindingResetRefusal::NothingToReset),
                NOTHING_TO_RESET,
            ),
            (C::NotRemoved(StoreError::IncompleteDeletion), RESET_FAILED),
            (
                C::Ambiguous(BindingResetAmbiguity::IncompleteDeletion),
                RESET_AMBIGUOUS,
            ),
            (
                C::Ambiguous(BindingResetAmbiguity::AbsenceNotConfirmed),
                RESET_AMBIGUOUS,
            ),
        ];

        for (refusal, expected) in cases {
            assert_eq!(reset_confirm_error(refusal), expected, "{refusal:?}");
        }
    }

    // -- redaction ------------------------------------------------------------

    #[test]
    fn debug_output_redacts_paths_ids_and_session_identity() {
        let f = fixture("b1j1-debug");

        let preparation = f.prepare();

        let text = format!("{preparation:?}");

        assert!(!text.contains(&preparation.preparation_id));
        assert!(!text.contains("target.lvault"));
        assert!(!text.contains("vault.lvault"));

        let token = f.state.begin_sync_binding_selection().unwrap();

        assert_eq!(format!("{token:?}"), "SessionToken(<redacted>)");

        f.bind();

        let linked = f.status();

        assert!(!format!("{linked:?}").contains("target.lvault"));

        let reset = prepare_reset_in(&f.state, &f.root).unwrap();

        let text = format!("{reset:?}");

        assert!(!text.contains(&reset.preparation_id));
        assert!(!text.contains("target.lvault"));

        // The error type carries only its two fixed strings.
        assert_eq!(
            format!("{TARGET_IS_VAULT:?}"),
            "CommandError { code: \"syncTargetIsVault\", message: \"The selected file is this vault's own file or one of its companion files.\" }"
        );
    }
}
