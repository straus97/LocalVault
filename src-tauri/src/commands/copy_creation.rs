//! Dormant Tauri command boundary over the session-owned creation of one new
//! encrypted copy of the unlocked vault (Stage 1U-4 B2b).
//!
//! The three commands here are NOT registered in `generate_handler!` (`lib.rs`):
//! no frontend wrapper, dialog or button reaches them until B2c. The dead-code
//! allowance below exists only for that interval and must be removed when they
//! are registered.
//!
//! The module is a thin shell. Every rule (one-time consumption, the 120-second
//! lifetime, the authenticated source snapshot, target absence, local-NTFS-only
//! publication, the handle-bound no-replace rename, independent read-back and
//! the exact definite/ambiguous outcomes) lives in the session methods that
//! [`AppState`] exposes; nothing here repeats or relaxes one. What this module
//! adds:
//!
//! * fixed, serializable shapes (DTOs) that carry only what a person needs to
//!   see, and a redacted `Debug` for every one that holds a path or an id;
//! * a fixed, sanitized [`CommandError`] for every outcome, from exhaustive
//!   matches over the B2a enums, so a new B2a variant forces a review here;
//! * the Rust-owned native SAVE dialog, and the check that the session and the
//!   attempt a selection is prepared for are the ones that opened the dialog.
//!
//! # Destination selection
//!
//! The frontend never supplies a path. `choose_and_prepare_copy_creation` opens
//! the native save dialog from Rust, filtered to `*.lvault`, with the
//! application-state mutex **not** held. The Windows save dialog (`IFileSaveDialog`
//! through the dialog plugin) only returns a name: it creates, truncates,
//! overwrites, renames and deletes nothing, and it is not the no-clobber
//! boundary, whatever overwrite warning it shows. The returned path is a
//! REQUEST: the extension is checked here and everything else (absent target,
//! existing parent, local NTFS, not a file of this vault, not UNC) by the
//! unchanged B2a preparation. An existing target is always refused. A selection is
//! never consent: nothing is created until a separate `confirm_copy_creation`
//! call with the Rust-issued preparation id.
//!
//! # Session and attempt ownership
//!
//! The dialog can outlive the unlocked session. A
//! [`SessionToken`](crate::app_state::SessionToken) is taken before it opens and
//! re-checked under the state mutex before B2a is called, so a destination chosen
//! for one session never prepares another. Nothing keeps the session alive while
//! the dialog is open, so a long-open dialog legitimately ends in a stale-session
//! refusal.
//!
//! Two dialog attempts of the SAME session are told apart by an attempt id (a
//! canonical UUID chosen by the caller, validated like a
//! [`BindingAttemptId`]), with the same bounded cancelled-id memory the binding
//! and reset flows use. Only the current attempt may prepare, only it can cancel
//! what it prepared, and a cancel that arrives before its own begin still wins.
//! The check happens BEFORE the session is asked to prepare, because a
//! preparation voids every other pending approval: an obsolete selection can
//! never void a newer binding, reset or copy approval.
//!
//! The attempt id is a correlation label. It is NOT the preparation id, is never
//! returned, approves nothing and never replaces the explicit confirmation.
//!
//! # Concurrent dialogs
//!
//! The save dialog takes the same process-wide picker slot as the binding file
//! picker, so the two never open together; a second request gets a fixed "busy"
//! error. The slot is an RAII guard released on every way out, and no lock is
//! held across the dialog.
//!
//! # Outcomes
//!
//! `NotPublished` without leftovers, `NotPublished` with a possible staging
//! leftover, `PublicationUnknown` and `CreatedUnverified` are different
//! filesystem states and keep different codes. Nothing is retried, deleted or
//! bound by this module, and no message suggests that a retry is safe or
//! automatic after an ambiguous outcome.
//!
//! Errors and `Debug` output never carry a path, password, key, fingerprint,
//! physical file identifier, raw I/O or native status, preparation id or attempt
//! id. Nothing here is logged.

// Dormant until B2c registers the commands (see the module comment).
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::{AppHandle, State, WebviewWindow};
use tauri_plugin_dialog::{DialogExt, FilePath};

use super::{
    sync_binding::{PickerSlot, Selection},
    CommandError,
};
use crate::{
    app_state::{AppState, AppStateError, BindingAttemptId},
    vault::{
        session::{
            CopyCreationConfirmRefusal, CopyCreationOutcome, CopyCreationPreview,
            CopyCreationRefusal, CopyCreationStale, NotPublishedReason, SyncStateUnavailable,
        },
        sync_file_adapter::SyncFileTarget,
        sync_state_store::SyncStateRoot,
    },
};

/// The name the save dialog proposes. A suggestion only: the user's choice is
/// validated like any other.
const SUGGESTED_FILE_NAME: &str = "LocalVault copy.lvault";

// -- Error codes ------------------------------------------------------------
//
// Fixed codes and messages. A message never names a path, an id or a value, and
// never claims that anything was synchronized, uploaded or enabled.

const fn error(code: &'static str, message: &'static str) -> CommandError {
    CommandError::new(code, message)
}

const FILE_DIALOG_CANCELLED: CommandError = error(
    "copyFileDialogCancelled",
    "No location was selected. Nothing was created.",
);

const FILE_DIALOG_BUSY: CommandError = error(
    "copyFileDialogBusy",
    "A file selection is already in progress.",
);

const SESSION_CHANGED: CommandError = error(
    "syncSessionChanged",
    "The vault session changed during the file selection. Start again.",
);

const ATTEMPT_INVALID: CommandError =
    error("copyAttemptInvalid", "The attempt identifier is invalid.");

const ATTEMPT_SUPERSEDED: CommandError = error(
    "copyAttemptSuperseded",
    "The file selection belongs to an attempt that is no longer current. Start again.",
);

const TARGET_INVALID: CommandError = error(
    "copyTargetInvalid",
    "The selected name is not a usable LocalVault file name. Nothing was created.",
);

const TARGET_EXISTS: CommandError = error(
    "copyTargetExists",
    "Something already exists at the selected location. Nothing was created or changed.",
);

const TARGET_IS_VAULT_FILE: CommandError = error(
    "copyTargetIsVaultFile",
    "The selected name belongs to this vault or its companion files. Nothing was created.",
);

const LOCATION_UNSUPPORTED: CommandError = error(
    "copyLocationUnsupported",
    "The copy can only be created in an existing folder on a local NTFS drive. Nothing was created.",
);

const TARGET_UNAVAILABLE: CommandError = error(
    "copyTargetUnavailable",
    "The selected location could not be inspected. Nothing was created.",
);

const SOURCE_CHANGED: CommandError = error(
    "copySourceChanged",
    "The vault file changed after the copy was reviewed. Nothing was created. Start again.",
);

const SOURCE_UNVERIFIABLE: CommandError = error(
    "copySourceUnverifiable",
    "The vault file could not be verified as the source of a copy. Nothing was created.",
);

const UNSAVED_CHANGES: CommandError = error(
    "copyUnsavedChanges",
    "The vault has unsaved changes. Save them before creating a copy. Nothing was created.",
);

const LEGACY_VAULT: CommandError = error(
    "copyLegacyVault",
    "This vault uses an older file version that cannot be copied this way. Nothing was created.",
);

const BINDING_EXISTS: CommandError = error(
    "copyBindingExists",
    "A synchronization binding record already exists for this vault. Nothing was created.",
);

const BINDING_STATE_CORRUPT: CommandError = error(
    "copyBindingStateCorrupt",
    "The stored synchronization binding record is unreadable or unsupported. Nothing was created.",
);

const NOT_PREPARED: CommandError = error(
    "copyNotPrepared",
    "The copy could not be prepared. Nothing was created.",
);

const PREPARATION_MISSING: CommandError = error(
    "copyPreparationMissing",
    "There is nothing waiting for confirmation. Start again.",
);

const PREPARATION_STALE: CommandError = error(
    "copyPreparationStale",
    "The confirmation is out of date. Nothing was created. Start again.",
);

const NOT_CREATED: CommandError = error("copyNotCreated", "The copy was not created.");

const NOT_CREATED_STAGING_REMAINS: CommandError = error(
    "copyNotCreatedStagingRemains",
    "The copy was not created, but a temporary file may remain in the selected folder. Check the folder before doing anything else.",
);

const PUBLICATION_UNKNOWN: CommandError = error(
    "copyPublicationUnknown",
    "Whether the copy was created could not be established. Check the selected folder before doing anything else. LocalVault deleted nothing.",
);

const CREATED_UNVERIFIED: CommandError = error(
    "copyCreatedUnverified",
    "A copy file exists or may exist, but it could not be verified. Do not use or link it before checking the folder. LocalVault left it in place.",
);

// -- Error mapping ----------------------------------------------------------

/// The outer ("no live session", or an attempt/session identity) error of an
/// application-state call.
fn app_error(error: AppStateError) -> CommandError {
    match error {
        AppStateError::SessionChanged => SESSION_CHANGED,
        AppStateError::AttemptSuperseded => ATTEMPT_SUPERSEDED,
        other => CommandError::from(other),
    }
}

fn unavailable_error(reason: SyncStateUnavailable) -> CommandError {
    match reason {
        SyncStateUnavailable::LocalVaultChanged => SOURCE_CHANGED,
        SyncStateUnavailable::LocalLocator | SyncStateUnavailable::Root => NOT_PREPARED,
    }
}

/// Refusals at preparation, and the same refusals at confirmation. Every one is
/// definite: nothing was written.
fn refusal_error(refusal: CopyCreationRefusal) -> CommandError {
    use CopyCreationRefusal as Refusal;

    match refusal {
        Refusal::UnsavedChanges => UNSAVED_CHANGES,
        Refusal::LegacyVault => LEGACY_VAULT,
        Refusal::BindingExists => BINDING_EXISTS,
        Refusal::BindingStateUnreadable => BINDING_STATE_CORRUPT,
        Refusal::TargetExists => TARGET_EXISTS,
        Refusal::TargetIsVaultFile => TARGET_IS_VAULT_FILE,
        Refusal::TargetLocationUnsupported => LOCATION_UNSUPPORTED,
        Refusal::TargetUnavailable => TARGET_UNAVAILABLE,
        Refusal::SourceIdentityUncertain => SOURCE_UNVERIFIABLE,
        Refusal::Unavailable(reason) => unavailable_error(reason),
        Refusal::Randomness => NOT_PREPARED,
    }
}

fn stale_error(stale: CopyCreationStale) -> CommandError {
    match stale {
        CopyCreationStale::NoPendingApproval => PREPARATION_MISSING,
        CopyCreationStale::NotCurrentPreparation | CopyCreationStale::Expired => PREPARATION_STALE,
        CopyCreationStale::LocalVaultChanged => SOURCE_CHANGED,
        CopyCreationStale::TargetAppeared => TARGET_EXISTS,
    }
}

/// The two definite "no target was published" states. The reason is diagnostic
/// only (no frontend decision depends on it), but it is matched exhaustively so
/// that a new reason forces a review of this mapping.
fn not_published_error(reason: NotPublishedReason, staging_remains: bool) -> CommandError {
    match reason {
        NotPublishedReason::StagingFailed
        | NotPublishedReason::WriteFailed
        | NotPublishedReason::VolumeNotLocalNtfs
        | NotPublishedReason::IdentityUncertain
        | NotPublishedReason::EvidenceChanged
        | NotPublishedReason::TargetAppeared
        | NotPublishedReason::RenameRefused => {}
    }

    if staging_remains {
        NOT_CREATED_STAGING_REMAINS
    } else {
        NOT_CREATED
    }
}

fn confirm_error(refusal: CopyCreationConfirmRefusal) -> CommandError {
    match refusal {
        CopyCreationConfirmRefusal::Stale(stale) => stale_error(stale),
        CopyCreationConfirmRefusal::Refused(refusal) => refusal_error(refusal),
        CopyCreationConfirmRefusal::NotPublished {
            reason,
            staging_remains,
        } => not_published_error(reason, staging_remains),
        CopyCreationConfirmRefusal::PublicationUnknown => PUBLICATION_UNKNOWN,
        CopyCreationConfirmRefusal::CreatedUnverified => CREATED_UNVERIFIED,
    }
}

// -- DTOs -------------------------------------------------------------------

/// What the person must be shown before confirming a copy. `target_path` is the
/// exact path Rust will create, returned only for a successfully prepared
/// destination. Nothing else about the source or the destination leaves Rust.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CopyCreationPreparationDto {
    pub preparation_id: String,
    pub vault_file_name: String,
    pub target_path: String,
}

impl std::fmt::Debug for CopyCreationPreparationDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CopyCreationPreparationDto(<redacted>)")
    }
}

impl From<&CopyCreationPreview> for CopyCreationPreparationDto {
    fn from(preview: &CopyCreationPreview) -> Self {
        Self {
            preparation_id: preview.preparation_id().to_owned(),
            vault_file_name: preview.vault_file_name().to_owned(),
            target_path: preview.target_path().to_owned(),
        }
    }
}

/// Fieldless on purpose. It means the file was published by the no-replace
/// primitive and independently read back with exactly the vault's bytes; it does
/// not mean the copy is bound, synchronized or durable across a power loss.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CopyCreationOutcomeDto {
    CreatedAndVerified,
}

impl From<CopyCreationOutcome> for CopyCreationOutcomeDto {
    fn from(outcome: CopyCreationOutcome) -> Self {
        match outcome {
            CopyCreationOutcome::CreatedAndVerified => Self::CreatedAndVerified,
        }
    }
}

// -- Destination selection --------------------------------------------------

fn classify_selection(picked: Option<FilePath>) -> Selection {
    match picked {
        None => Selection::Cancelled,
        Some(file) => match file.into_path() {
            Ok(path) => Selection::Chosen(path),
            Err(_) => Selection::Unusable,
        },
    }
}

/// The dialog's filter is a hint the user can override; this is the check.
fn has_vault_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lvault"))
}

/// Opens the native save dialog. Blocks until the user answers, so it must run
/// off the main thread (the command that calls it is `async`) and with no lock
/// held. It returns a name only; it creates nothing.
fn pick_copy_target(app: &AppHandle, window: &WebviewWindow) -> Selection {
    classify_selection(
        app.dialog()
            .file()
            .set_title("Create a new encrypted LocalVault copy")
            .add_filter("LocalVault vault", &["lvault"])
            .set_file_name(SUGGESTED_FILE_NAME)
            .set_parent(window)
            .blocking_save_file(),
    )
}

/// Runs `run` while holding the process-wide picker slot shared with the binding
/// file picker, or refuses with a fixed error without running it. The slot is
/// released when `run` returns, whatever it returns.
fn with_picker<T>(run: impl FnOnce() -> Result<T, CommandError>) -> Result<T, CommandError> {
    let _slot = PickerSlot::acquire().ok_or(FILE_DIALOG_BUSY)?;

    run()
}

// -- Testable operations ----------------------------------------------------
//
// The commands below only resolve the trusted root and the dialog; everything
// else is here, free of Tauri, so it can be exercised against a real `AppState`.

fn parse_attempt(text: &str) -> Result<BindingAttemptId, CommandError> {
    BindingAttemptId::parse(text).ok_or(ATTEMPT_INVALID)
}

/// Void this flow's older preparation, take the session identity and make
/// `attempt` the current one, run `pick` with no lock held, then ask B2a to
/// prepare the chosen name for that same session and that same attempt only.
fn choose_and_prepare_in(
    state: &AppState,
    root: &SyncStateRoot,
    attempt: BindingAttemptId,
    pick: impl FnOnce() -> Selection,
) -> Result<CopyCreationPreparationDto, CommandError> {
    let token = state
        .begin_copy_creation_selection(attempt)
        .map_err(app_error)?;

    let abandon = |attempt: BindingAttemptId| {
        // Idempotent and best effort. It acts only if `attempt` is still the
        // current one, so a newer attempt's approval is never discarded.
        let _ = state.cancel_copy_creation_attempt(attempt);
    };

    let path: PathBuf = match pick() {
        Selection::Chosen(path) => path,
        Selection::Cancelled => {
            abandon(attempt);
            return Err(FILE_DIALOG_CANCELLED);
        }
        Selection::Unusable => {
            abandon(attempt);
            return Err(TARGET_INVALID);
        }
    };

    let target = if has_vault_extension(&path) {
        SyncFileTarget::from_path(&path).ok()
    } else {
        None
    };

    let Some(target) = target else {
        abandon(attempt);
        return Err(TARGET_INVALID);
    };

    match state.prepare_copy_creation_for_session(token, attempt, root, &target) {
        Err(error) => Err(app_error(error)),
        Ok(Err(refusal)) => Err(refusal_error(refusal)),
        Ok(Ok(preview)) => Ok(CopyCreationPreparationDto::from(&preview)),
    }
}

fn confirm_in(
    state: &AppState,
    root: &SyncStateRoot,
    preparation_id: &str,
) -> Result<CopyCreationOutcomeDto, CommandError> {
    match state.confirm_copy_creation(root, preparation_id) {
        Err(error) => Err(app_error(error)),
        Ok(Err(refusal)) => Err(confirm_error(refusal)),
        Ok(Ok(outcome)) => Ok(CopyCreationOutcomeDto::from(outcome)),
    }
}

fn trusted_root(app: &AppHandle) -> Result<SyncStateRoot, CommandError> {
    SyncStateRoot::from_app(app).map_err(|_| NOT_PREPARED)
}

// -- Commands (not registered) ----------------------------------------------

/// Open the native save dialog for a NEW `*.lvault` name and prepare a copy
/// there. Creates nothing: the selection is not consent. `attempt_id` labels this
/// attempt (see the module comment); it is not a path and not an approval.
#[tauri::command(async)]
pub fn choose_and_prepare_copy_creation(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    attempt_id: String,
) -> Result<CopyCreationPreparationDto, CommandError> {
    let attempt = parse_attempt(&attempt_id)?;

    let root = trusted_root(&app)?;

    with_picker(|| {
        choose_and_prepare_in(&state, &root, attempt, || pick_copy_target(&app, &window))
    })
}

/// Create the copy that `preparation_id` (issued by Rust) names. The only input
/// is that id: no path, no bytes, no flag. Every call spends the preparation.
#[tauri::command(async)]
pub fn confirm_copy_creation(
    app: AppHandle,
    state: State<'_, AppState>,
    preparation_id: String,
) -> Result<CopyCreationOutcomeDto, CommandError> {
    let root = trusted_root(&app)?;

    confirm_in(&state, &root, &preparation_id)
}

/// Cancel one attempt: it can no longer prepare, and if it is the current attempt
/// its pending preparation is discarded. A stale attempt discards nothing.
///
/// `async` so that it never blocks the main thread behind a confirmation that is
/// still holding the state mutex.
#[tauri::command(async)]
pub fn cancel_copy_creation(
    state: State<'_, AppState>,
    attempt_id: String,
) -> Result<(), CommandError> {
    let attempt = parse_attempt(&attempt_id)?;

    state
        .cancel_copy_creation_attempt(attempt)
        .map_err(app_error)
}

#[cfg(all(test, windows))]
mod tests {
    use std::{cell::Cell, fs};

    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        commands::sync_binding::PICKER_SLOT_TEST_LOCK,
        vault::{
            session::{BindingResetOutcome, BindingState, InitialBindingOutcome},
            sync_state_store::SYNC_STATE_DIRECTORY,
        },
    };

    // The flow tests run the real session, the real B2a publication and the real
    // `AppState` against scratch under the git-ignored
    // `.qa-local/sync-copy-b2-tests/` (never `%TEMP%`). Nothing opens a native
    // dialog: the dialog is exercised only through its result type, and the UI is
    // not tested.

    const PASSWORD: &str = "copy-creation-command-test-only-password";

    const SOME_ID: &str = "00000000-0000-4000-8000-000000000000";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(PASSWORD.to_owned())
    }

    fn attempt() -> BindingAttemptId {
        BindingAttemptId::parse(&uuid::Uuid::new_v4().to_string()).unwrap()
    }

    fn qa_scratch(name: &str) -> tempfile::TempDir {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("sync-copy-b2-tests");

        fs::create_dir_all(&base).unwrap();

        tempfile::Builder::new()
            .prefix(&format!("{name}-"))
            .tempdir_in(&base)
            .unwrap()
    }

    /// An unlocked synthetic vault with no binding and an existing, empty `dest`
    /// folder. `state` is declared first so the session (and its exclusive lock
    /// file) drops before the scratch directory is removed.
    struct Fixture {
        state: AppState,
        root: SyncStateRoot,
        app_local: PathBuf,
        vault: PathBuf,
        dest: PathBuf,
        target: PathBuf,
        _scratch: tempfile::TempDir,
    }

    fn fixture(name: &str) -> Fixture {
        let scratch = qa_scratch(name);
        let vaults = scratch.path().join("vaults");
        let dest = scratch.path().join("dest");

        fs::create_dir_all(&vaults).unwrap();
        fs::create_dir_all(&dest).unwrap();

        let vault = vaults.join("vault.lvault");
        let app_local = scratch.path().join("app-local");
        let state = AppState::default();

        state.create_vault(vault.clone(), password()).unwrap();
        state.lock_vault().unwrap();
        state.unlock_vault(vault.clone(), password()).unwrap();

        Fixture {
            root: SyncStateRoot::for_test(app_local.clone()),
            target: dest.join("copy.lvault"),
            state,
            app_local,
            vault,
            dest,
            _scratch: scratch,
        }
    }

    impl Fixture {
        fn choose_path_as(
            &self,
            attempt: BindingAttemptId,
            path: &Path,
        ) -> Result<CopyCreationPreparationDto, CommandError> {
            choose_and_prepare_in(&self.state, &self.root, attempt, || {
                Selection::Chosen(path.to_owned())
            })
        }

        fn choose_path(&self, path: &Path) -> Result<CopyCreationPreparationDto, CommandError> {
            self.choose_path_as(attempt(), path)
        }

        fn prepare(&self) -> CopyCreationPreparationDto {
            self.choose_path(&self.target).unwrap()
        }

        fn confirm(&self, id: &str) -> Result<CopyCreationOutcomeDto, CommandError> {
            confirm_in(&self.state, &self.root, id)
        }

        fn create_copy(&self) {
            let preparation = self.prepare();

            assert_eq!(
                self.confirm(&preparation.preparation_id),
                Ok(CopyCreationOutcomeDto::CreatedAndVerified)
            );
        }

        fn relock_and_unlock(&self) {
            self.state.lock_vault().unwrap();
            self.state
                .unlock_vault(self.vault.clone(), password())
                .unwrap();
        }

        /// Every entry of the destination folder (a target or a staging file).
        fn dest_entries(&self) -> Vec<String> {
            let mut names: Vec<_> = fs::read_dir(&self.dest)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();

            names.sort();

            names
        }

        fn assert_nothing_created(&self) {
            assert_eq!(self.dest_entries(), Vec::<String>::new());
        }

        /// No preparation is pending (a confirmation finds nothing to spend).
        fn assert_nothing_pending(&self) {
            assert_eq!(self.confirm(SOME_ID), Err(PREPARATION_MISSING));
        }

        fn record_files(&self) -> Vec<PathBuf> {
            fs::read_dir(self.app_local.join(SYNC_STATE_DIRECTORY))
                .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
                .unwrap_or_default()
        }

        fn assert_still_unbound(&self) {
            let status = self.state.binding_status(&self.root).unwrap();

            assert!(matches!(status.state(), BindingState::NotConfigured));
            assert!(self.record_files().is_empty());
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

    // -- A. DTOs and redaction ----------------------------------------------

    #[test]
    fn the_preparation_carries_only_the_reviewed_values_and_is_redacted() {
        let f = fixture("b2b-dto");

        let preparation = f.prepare();

        assert_eq!(preparation.vault_file_name, "vault.lvault");
        assert_eq!(preparation.target_path, f.target.to_str().unwrap());
        assert!(uuid::Uuid::parse_str(&preparation.preparation_id).is_ok());

        assert_eq!(
            sorted_keys(&preparation),
            ["preparationId", "targetPath", "vaultFileName"]
        );

        let debug = format!("{preparation:?}");

        assert_eq!(debug, "CopyCreationPreparationDto(<redacted>)");
        assert!(!debug.contains(&preparation.preparation_id));
        assert!(!debug.contains("copy.lvault"));

        // Preparing writes nothing, anywhere.
        f.assert_nothing_created();
        f.assert_still_unbound();
    }

    #[test]
    fn the_outcome_is_fieldless_and_claims_nothing_beyond_creation() {
        assert_eq!(
            json(&CopyCreationOutcomeDto::CreatedAndVerified),
            "\"createdAndVerified\""
        );
        assert_eq!(
            CopyCreationOutcomeDto::from(CopyCreationOutcome::CreatedAndVerified),
            CopyCreationOutcomeDto::CreatedAndVerified
        );
    }

    // -- B. Exact error mapping ---------------------------------------------

    fn code(error: CommandError) -> &'static str {
        error.code
    }

    #[test]
    fn every_refusal_maps_to_one_fixed_code() {
        use CopyCreationRefusal as R;

        let cases = [
            (R::UnsavedChanges, "copyUnsavedChanges"),
            (R::LegacyVault, "copyLegacyVault"),
            (R::BindingExists, "copyBindingExists"),
            (R::BindingStateUnreadable, "copyBindingStateCorrupt"),
            (R::TargetExists, "copyTargetExists"),
            (R::TargetIsVaultFile, "copyTargetIsVaultFile"),
            (R::TargetLocationUnsupported, "copyLocationUnsupported"),
            (R::TargetUnavailable, "copyTargetUnavailable"),
            (R::SourceIdentityUncertain, "copySourceUnverifiable"),
            (
                R::Unavailable(SyncStateUnavailable::LocalVaultChanged),
                "copySourceChanged",
            ),
            (
                R::Unavailable(SyncStateUnavailable::LocalLocator),
                "copyNotPrepared",
            ),
            (
                R::Unavailable(SyncStateUnavailable::Root),
                "copyNotPrepared",
            ),
            (R::Randomness, "copyNotPrepared"),
        ];

        for (refusal, expected) in cases {
            assert_eq!(code(refusal_error(refusal)), expected, "{refusal:?}");

            // The same refusal at confirmation is the same definite error.
            assert_eq!(
                confirm_error(CopyCreationConfirmRefusal::Refused(refusal)),
                refusal_error(refusal)
            );
        }
    }

    #[test]
    fn every_stale_reason_maps_to_one_fixed_code() {
        use CopyCreationStale as S;

        let cases = [
            (S::NoPendingApproval, "copyPreparationMissing"),
            (S::NotCurrentPreparation, "copyPreparationStale"),
            (S::Expired, "copyPreparationStale"),
            (S::LocalVaultChanged, "copySourceChanged"),
            (S::TargetAppeared, "copyTargetExists"),
        ];

        for (stale, expected) in cases {
            assert_eq!(
                code(confirm_error(CopyCreationConfirmRefusal::Stale(stale))),
                expected,
                "{stale:?}"
            );
        }
    }

    const ALL_REASONS: [NotPublishedReason; 7] = [
        NotPublishedReason::StagingFailed,
        NotPublishedReason::WriteFailed,
        NotPublishedReason::VolumeNotLocalNtfs,
        NotPublishedReason::IdentityUncertain,
        NotPublishedReason::EvidenceChanged,
        NotPublishedReason::TargetAppeared,
        NotPublishedReason::RenameRefused,
    ];

    #[test]
    fn definite_and_ambiguous_outcomes_keep_four_distinct_codes() {
        for reason in ALL_REASONS {
            assert_eq!(
                confirm_error(CopyCreationConfirmRefusal::NotPublished {
                    reason,
                    staging_remains: false,
                }),
                NOT_CREATED,
                "{reason:?}"
            );
            assert_eq!(
                confirm_error(CopyCreationConfirmRefusal::NotPublished {
                    reason,
                    staging_remains: true,
                }),
                NOT_CREATED_STAGING_REMAINS,
                "{reason:?}"
            );
        }

        let four = [
            confirm_error(CopyCreationConfirmRefusal::NotPublished {
                reason: NotPublishedReason::RenameRefused,
                staging_remains: false,
            }),
            confirm_error(CopyCreationConfirmRefusal::NotPublished {
                reason: NotPublishedReason::RenameRefused,
                staging_remains: true,
            }),
            confirm_error(CopyCreationConfirmRefusal::PublicationUnknown),
            confirm_error(CopyCreationConfirmRefusal::CreatedUnverified),
        ];

        assert_eq!(
            four.clone().map(code),
            [
                "copyNotCreated",
                "copyNotCreatedStagingRemains",
                "copyPublicationUnknown",
                "copyCreatedUnverified",
            ]
        );

        // Different filesystem states never share a code or a message.
        for (index, left) in four.iter().enumerate() {
            for right in &four[index + 1..] {
                assert_ne!(left.code, right.code);
                assert_ne!(left.message, right.message);
            }
        }
    }

    #[test]
    fn ambiguous_messages_never_suggest_a_retry_or_a_cleanup() {
        for error in [
            NOT_CREATED_STAGING_REMAINS,
            PUBLICATION_UNKNOWN,
            CREATED_UNVERIFIED,
        ] {
            let message = error.message.to_lowercase();

            for word in ["retry", "try again", "start again", "automatic", "removed"] {
                assert!(!message.contains(word), "{}: {word}", error.code);
            }

            assert!(message.contains("check"), "{}", error.code);
        }

        // Only an ambiguous outcome says that nothing was deleted or left alone.
        assert!(PUBLICATION_UNKNOWN.message.contains("deleted nothing"));
        assert!(CREATED_UNVERIFIED.message.contains("left it in place"));
    }

    #[test]
    fn app_state_errors_use_the_shared_and_the_copy_codes() {
        assert_eq!(code(app_error(AppStateError::VaultLocked)), "vaultLocked");
        assert_eq!(
            code(app_error(AppStateError::SessionExpired)),
            "vaultSessionExpired"
        );
        assert_eq!(
            code(app_error(AppStateError::SessionChanged)),
            "syncSessionChanged"
        );
        assert_eq!(
            code(app_error(AppStateError::AttemptSuperseded)),
            "copyAttemptSuperseded"
        );
        assert_eq!(code(ATTEMPT_INVALID), "copyAttemptInvalid");
        assert_eq!(code(FILE_DIALOG_BUSY), "copyFileDialogBusy");
        assert_eq!(code(FILE_DIALOG_CANCELLED), "copyFileDialogCancelled");
        assert_eq!(code(TARGET_INVALID), "copyTargetInvalid");
    }

    #[test]
    fn no_message_names_a_path_a_secret_or_a_native_detail() {
        let all = [
            FILE_DIALOG_CANCELLED,
            FILE_DIALOG_BUSY,
            SESSION_CHANGED,
            ATTEMPT_INVALID,
            ATTEMPT_SUPERSEDED,
            TARGET_INVALID,
            TARGET_EXISTS,
            TARGET_IS_VAULT_FILE,
            LOCATION_UNSUPPORTED,
            TARGET_UNAVAILABLE,
            SOURCE_CHANGED,
            SOURCE_UNVERIFIABLE,
            UNSAVED_CHANGES,
            LEGACY_VAULT,
            BINDING_EXISTS,
            BINDING_STATE_CORRUPT,
            NOT_PREPARED,
            PREPARATION_MISSING,
            PREPARATION_STALE,
            NOT_CREATED,
            NOT_CREATED_STAGING_REMAINS,
            PUBLICATION_UNKNOWN,
            CREATED_UNVERIFIED,
        ];

        for error in all {
            assert!(error.code.starts_with("copy") || error.code == "syncSessionChanged");

            for text in [error.code, error.message] {
                for forbidden in ["\\", "/", ".lvault", "0x", "NTSTATUS", "password", "key"] {
                    assert!(!text.contains(forbidden), "{}: {forbidden}", error.code);
                }
            }

            // Nothing claims that anything was synchronized or enabled.
            for word in ["synced", "synchronized", "uploaded", "cloud", "enabled"] {
                assert!(
                    !error.message.to_lowercase().contains(word),
                    "{}",
                    error.code
                );
            }
        }
    }

    // -- C-E. Selection policy and the B2a boundary --------------------------

    #[test]
    fn a_picker_result_is_classified_before_any_validation() {
        assert_eq!(classify_selection(None), Selection::Cancelled);

        let path = PathBuf::from(r"C:\copies\copy.lvault");

        assert_eq!(
            classify_selection(Some(FilePath::Path(path.clone()))),
            Selection::Chosen(path)
        );

        let web = url::Url::parse("https://example.invalid/copy.lvault").unwrap();

        assert_eq!(
            classify_selection(Some(FilePath::Url(web))),
            Selection::Unusable
        );
    }

    #[test]
    fn only_lvault_names_pass_the_extension_check() {
        assert!(has_vault_extension(Path::new(r"C:\a\copy.lvault")));
        assert!(has_vault_extension(Path::new(r"C:\a\copy.LVAULT")));

        assert!(!has_vault_extension(Path::new(r"C:\a\copy.lvault.bak")));
        assert!(!has_vault_extension(Path::new(r"C:\a\copy.txt")));
        assert!(!has_vault_extension(Path::new(r"C:\a\copy")));
        assert!(!has_vault_extension(Path::new(r"C:\a\.lvault")));
        assert!(!has_vault_extension(Path::new(r"C:\a\")));
    }

    #[test]
    fn a_cancelled_dialog_writes_nothing_and_leaves_no_approval() {
        let f = fixture("b2b-cancelled");

        let older = f.prepare();

        let result = choose_and_prepare_in(&f.state, &f.root, attempt(), || Selection::Cancelled);

        assert_eq!(result, Err(FILE_DIALOG_CANCELLED));

        // The older approval of this flow was voided by the new selection.
        assert_eq!(f.confirm(&older.preparation_id), Err(PREPARATION_MISSING));

        f.assert_nothing_created();
        f.assert_still_unbound();
    }

    #[test]
    fn an_unusable_selection_prepares_nothing_and_voids_the_older_approval() {
        let f = fixture("b2b-invalid");

        let wrong_extension = f.dest.join("copy.txt");
        let no_extension = f.dest.join("copy");

        for selection in [
            Selection::Unusable,
            Selection::Chosen(wrong_extension),
            Selection::Chosen(no_extension),
            Selection::Chosen(PathBuf::from("relative.lvault")),
            Selection::Chosen(PathBuf::new()),
        ] {
            let older = f.prepare();

            assert_eq!(
                choose_and_prepare_in(&f.state, &f.root, attempt(), || selection),
                Err(TARGET_INVALID)
            );

            assert_eq!(f.confirm(&older.preparation_id), Err(PREPARATION_MISSING));
        }

        f.assert_nothing_created();
    }

    #[test]
    fn an_existing_target_is_refused_and_left_exactly_as_it_was() {
        let f = fixture("b2b-existing");

        fs::write(&f.target, b"precious bytes").unwrap();

        let older = f.choose_path(&f.dest.join("other.lvault")).unwrap();

        assert_eq!(f.choose_path(&f.target), Err(TARGET_EXISTS));

        assert_eq!(fs::read(&f.target).unwrap(), b"precious bytes");
        assert_eq!(f.dest_entries(), ["copy.lvault"]);

        // The refused selection voided the older approval, so it cannot be used
        // to write anywhere.
        assert_eq!(f.confirm(&older.preparation_id), Err(PREPARATION_MISSING));
        assert!(!f.dest.join("other.lvault").exists());
    }

    #[test]
    fn a_target_that_appears_after_the_review_is_never_replaced() {
        let f = fixture("b2b-appeared");

        let preparation = f.prepare();

        fs::write(&f.target, b"created by someone else").unwrap();

        assert_eq!(f.confirm(&preparation.preparation_id), Err(TARGET_EXISTS));

        assert_eq!(fs::read(&f.target).unwrap(), b"created by someone else");
        assert_eq!(f.dest_entries(), ["copy.lvault"]);
    }

    #[test]
    fn a_name_the_dialog_returned_is_still_checked_by_the_guarded_preparation() {
        let f = fixture("b2b-b2a-decides");

        // A folder that does not exist is never created.
        let missing_parent = f.dest.join("missing").join("copy.lvault");

        assert_eq!(f.choose_path(&missing_parent), Err(LOCATION_UNSUPPORTED));
        assert!(!f.dest.join("missing").exists());

        // The vault itself is never a copy's name.
        let before = fs::read(&f.vault).unwrap();

        assert_eq!(f.choose_path(&f.vault), Err(TARGET_IS_VAULT_FILE));
        assert_eq!(fs::read(&f.vault).unwrap(), before);

        // A directory with a vault name is not an absent target.
        let directory = f.dest.join("folder.lvault");

        fs::create_dir(&directory).unwrap();

        assert_eq!(f.choose_path(&directory), Err(LOCATION_UNSUPPORTED));
        assert!(directory.is_dir());

        // A network path is refused before anything touches it.
        let unc = PathBuf::from(r"\\localvault-test.invalid\share\copy.lvault");

        assert!(matches!(
            f.choose_path(&unc),
            Err(error) if error == LOCATION_UNSUPPORTED || error == TARGET_INVALID
        ));

        // Nothing was created besides what the test made.
        assert_eq!(f.dest_entries(), ["folder.lvault"]);
        f.assert_still_unbound();
    }

    // -- F, M. The frontend supplies no path ----------------------------------

    #[test]
    fn the_only_inputs_are_an_attempt_label_and_a_preparation_id() {
        let f = fixture("b2b-no-path");

        // An attempt label is a canonical UUID, never a path.
        for bad in [
            "",
            "not-an-id",
            r"C:\copies\copy.lvault",
            f.target.to_str().unwrap(),
            "00000000000040008000000000000000",
            "{00000000-0000-4000-8000-000000000000}",
            "urn:uuid:00000000-0000-4000-8000-000000000000",
            "00000000-0000-4000-8000-00000000000g",
        ] {
            assert_eq!(parse_attempt(bad), Err(ATTEMPT_INVALID), "{bad:?}");
        }

        let text = uuid::Uuid::new_v4().to_string();
        let parsed = parse_attempt(&text).unwrap();

        assert!(!format!("{parsed:?}").contains(&text));

        // A confirmation that names a path (or anything but the issued id) is
        // stale: it creates nothing there and spends the preparation.
        let preparation = f.prepare();

        for presented in [
            f.target.to_str().unwrap(),
            r"C:\copies\other.lvault",
            "../escape.lvault",
        ] {
            assert_eq!(
                f.confirm(presented),
                Err(PREPARATION_STALE),
                "{presented:?}"
            );
            assert_eq!(
                f.confirm(&preparation.preparation_id),
                Err(PREPARATION_MISSING)
            );

            f.assert_nothing_created();

            // Prepare again for the next presented value.
            let _ = f.prepare();
        }

        f.assert_nothing_created();
    }

    // -- G, H. Attempt ownership ---------------------------------------------

    #[test]
    fn a_dialog_finishing_late_cannot_prepare_or_cancel_the_next_dialogs_approval() {
        let f = fixture("b2b-late-dialog");

        let (a, b) = (attempt(), attempt());

        let target_a = f.dest.join("a.lvault");
        let target_b = f.dest.join("b.lvault");

        let mut b_id = String::new();

        let result = choose_and_prepare_in(&f.state, &f.root, a, || {
            // Dialog A is closed while its picker is open ...
            f.state.cancel_copy_creation_attempt(a).unwrap();

            // ... dialog B opens and prepares while A's picker still hangs ...
            b_id = f.choose_path_as(b, &target_b).unwrap().preparation_id;

            // ... and A's picker finally returns a name.
            Selection::Chosen(target_a.clone())
        });

        // A neither prepared (it would have replaced B's approval) nor cancelled.
        assert_eq!(result, Err(ATTEMPT_SUPERSEDED));

        // A's cancel arrives again, late: harmless.
        f.state.cancel_copy_creation_attempt(a).unwrap();

        assert_eq!(
            f.confirm(&b_id),
            Ok(CopyCreationOutcomeDto::CreatedAndVerified)
        );

        assert_eq!(f.dest_entries(), ["b.lvault"]);
        assert!(!target_a.exists());
    }

    #[test]
    fn a_dialog_superseded_without_a_cancel_prepares_nothing() {
        let f = fixture("b2b-superseded");

        let (a, b) = (attempt(), attempt());

        let target_b = f.dest.join("b.lvault");

        let mut b_id = String::new();

        let result = choose_and_prepare_in(&f.state, &f.root, a, || {
            b_id = f.choose_path_as(b, &target_b).unwrap().preparation_id;

            Selection::Chosen(f.dest.join("a.lvault"))
        });

        assert_eq!(result, Err(ATTEMPT_SUPERSEDED));

        assert_eq!(
            f.confirm(&b_id),
            Ok(CopyCreationOutcomeDto::CreatedAndVerified)
        );
        assert_eq!(f.dest_entries(), ["b.lvault"]);
    }

    #[test]
    fn a_late_cancel_of_an_old_attempt_leaves_a_newer_preparation_valid() {
        let f = fixture("b2b-late-cancel");

        let (a, b) = (attempt(), attempt());

        let _older = f.choose_path_as(a, &f.dest.join("a.lvault")).unwrap();
        let newer = f.choose_path_as(b, &f.dest.join("b.lvault")).unwrap();

        f.state.cancel_copy_creation_attempt(a).unwrap();

        assert_eq!(
            f.confirm(&newer.preparation_id),
            Ok(CopyCreationOutcomeDto::CreatedAndVerified)
        );
        assert_eq!(f.dest_entries(), ["b.lvault"]);
    }

    #[test]
    fn a_late_cancel_arriving_while_the_next_dialog_is_open_is_harmless() {
        let f = fixture("b2b-late-cancel-during-dialog");

        let (a, b) = (attempt(), attempt());

        let _older = f.choose_path_as(a, &f.dest.join("a.lvault")).unwrap();

        let prepared = choose_and_prepare_in(&f.state, &f.root, b, || {
            f.state.cancel_copy_creation_attempt(a).unwrap();

            Selection::Chosen(f.dest.join("b.lvault"))
        })
        .unwrap();

        assert_eq!(
            f.confirm(&prepared.preparation_id),
            Ok(CopyCreationOutcomeDto::CreatedAndVerified)
        );
    }

    #[test]
    fn a_cancel_that_overtakes_its_own_begin_still_wins() {
        let f = fixture("b2b-cancel-first");

        let a = attempt();

        f.state.cancel_copy_creation_attempt(a).unwrap();

        let opened = Cell::new(false);

        let result = choose_and_prepare_in(&f.state, &f.root, a, || {
            opened.set(true);

            Selection::Chosen(f.target.clone())
        });

        assert_eq!(result, Err(ATTEMPT_SUPERSEDED));
        assert!(
            !opened.get(),
            "a cancelled attempt must not open the dialog"
        );

        f.assert_nothing_pending();
        f.assert_nothing_created();
    }

    #[test]
    fn repeated_close_and_reopen_leaves_no_orphaned_approval() {
        let f = fixture("b2b-close-reopen");

        for _ in 0..20 {
            // Closed while the dialog is open.
            let a = attempt();

            assert_eq!(
                choose_and_prepare_in(&f.state, &f.root, a, || {
                    f.state.cancel_copy_creation_attempt(a).unwrap();

                    Selection::Chosen(f.target.clone())
                }),
                Err(ATTEMPT_SUPERSEDED)
            );

            f.assert_nothing_pending();

            // Closed with a review showing.
            let b = attempt();

            let preview = f.choose_path_as(b, &f.target).unwrap();

            f.state.cancel_copy_creation_attempt(b).unwrap();

            assert_eq!(f.confirm(&preview.preparation_id), Err(PREPARATION_MISSING));

            f.assert_nothing_pending();
        }

        f.assert_nothing_created();
        f.assert_still_unbound();
    }

    #[test]
    fn a_correctly_owned_cancel_clears_its_own_preparation_and_is_idempotent() {
        let f = fixture("b2b-owned-cancel");

        let a = attempt();

        let preview = f.choose_path_as(a, &f.target).unwrap();

        f.state.cancel_copy_creation_attempt(a).unwrap();
        f.state.cancel_copy_creation_attempt(a).unwrap();

        assert_eq!(f.confirm(&preview.preparation_id), Err(PREPARATION_MISSING));
        f.assert_nothing_created();
    }

    #[test]
    fn cancelling_an_unrelated_attempt_discards_nothing() {
        let f = fixture("b2b-unrelated-cancel");

        let preview = f.prepare();

        f.state.cancel_copy_creation_attempt(attempt()).unwrap();

        assert_eq!(
            f.confirm(&preview.preparation_id),
            Ok(CopyCreationOutcomeDto::CreatedAndVerified)
        );
    }

    #[test]
    fn an_attempt_id_is_not_an_approval_and_not_the_preparation_id() {
        let f = fixture("b2b-attempt-not-consent");

        let text = uuid::Uuid::new_v4().to_string();
        let a = BindingAttemptId::parse(&text).unwrap();

        let preview = f.choose_path_as(a, &f.target).unwrap();

        assert_ne!(preview.preparation_id, text);

        // Presenting the label as consent creates nothing and spends the review.
        assert_eq!(f.confirm(&text), Err(PREPARATION_STALE));
        assert_eq!(f.confirm(&preview.preparation_id), Err(PREPARATION_MISSING));

        f.assert_nothing_created();
    }

    #[test]
    fn a_refused_preparation_spends_its_attempt() {
        let f = fixture("b2b-refusal-spends-attempt");

        let a = attempt();
        let state = &f.state;

        // Refused (the vault itself), then the same attempt may not prepare again.
        let token = state.begin_copy_creation_selection(a).unwrap();
        let target = SyncFileTarget::from_path(&f.vault).unwrap();

        assert!(state
            .prepare_copy_creation_for_session(token, a, &f.root, &target)
            .unwrap()
            .is_err());

        let target = SyncFileTarget::from_path(&f.target).unwrap();

        assert!(matches!(
            state.prepare_copy_creation_for_session(token, a, &f.root, &target),
            Err(AppStateError::AttemptSuperseded)
        ));

        f.assert_nothing_created();
    }

    // -- I. Session identity across the dialog --------------------------------

    #[test]
    fn a_session_replaced_during_the_dialog_prepares_nothing() {
        let f = fixture("b2b-session-switch");

        let result = choose_and_prepare_in(&f.state, &f.root, attempt(), || {
            f.relock_and_unlock();

            Selection::Chosen(f.target.clone())
        });

        assert_eq!(result, Err(SESSION_CHANGED));

        // Nothing is pending in the new session either, and the chosen name was
        // not silently reused.
        f.assert_nothing_pending();
        f.assert_nothing_created();
    }

    #[test]
    fn a_session_locked_during_the_dialog_fails_closed() {
        let f = fixture("b2b-session-locked");

        let result = choose_and_prepare_in(&f.state, &f.root, attempt(), || {
            f.state.lock_vault().unwrap();

            Selection::Chosen(f.target.clone())
        });

        assert_eq!(result, Err(CommandError::from(AppStateError::VaultLocked)));

        f.state.unlock_vault(f.vault.clone(), password()).unwrap();

        f.assert_nothing_pending();
        f.assert_nothing_created();
    }

    #[test]
    fn an_old_dialog_after_a_session_replacement_fails_closed_and_spares_the_new_one() {
        let f = fixture("b2b-old-dialog-new-session");

        let (a, b) = (attempt(), attempt());

        let target_b = f.dest.join("b.lvault");

        let mut b_id = String::new();

        let result = choose_and_prepare_in(&f.state, &f.root, a, || {
            // The same vault, locked and unlocked again, and a new attempt there.
            f.relock_and_unlock();

            b_id = f.choose_path_as(b, &target_b).unwrap().preparation_id;

            // The old dialog's cancel and picker both arrive late.
            f.state.cancel_copy_creation_attempt(a).unwrap();

            Selection::Chosen(f.dest.join("a.lvault"))
        });

        assert_eq!(result, Err(SESSION_CHANGED));

        assert_eq!(
            f.confirm(&b_id),
            Ok(CopyCreationOutcomeDto::CreatedAndVerified)
        );
        assert_eq!(f.dest_entries(), ["b.lvault"]);
    }

    #[test]
    fn a_dialog_cannot_start_without_a_live_session() {
        let f = fixture("b2b-dialog-locked");

        f.state.lock_vault().unwrap();

        let opened = Cell::new(false);

        let result = choose_and_prepare_in(&f.state, &f.root, attempt(), || {
            opened.set(true);

            Selection::Cancelled
        });

        assert_eq!(result, Err(CommandError::from(AppStateError::VaultLocked)));
        assert!(!opened.get(), "the dialog must not open for a locked vault");
    }

    #[test]
    fn the_dialog_runs_without_the_state_mutex() {
        let f = fixture("b2b-no-mutex");

        // Locking needs the state mutex. Were it held across the dialog this
        // would deadlock instead of failing.
        let result = choose_and_prepare_in(&f.state, &f.root, attempt(), || {
            f.state.lock_vault().unwrap();

            Selection::Chosen(f.target.clone())
        });

        assert_eq!(result, Err(CommandError::from(AppStateError::VaultLocked)));
    }

    // -- J. Native dialog exclusion --------------------------------------------

    fn slot_is_free() -> bool {
        PickerSlot::acquire().is_some()
    }

    #[test]
    fn the_save_dialog_shares_the_binding_pickers_exclusion() {
        let _serial = PICKER_SLOT_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // A binding picker (or any holder of the slot) makes the save dialog
        // busy, and the closure never runs.
        let holder = PickerSlot::acquire().expect("the slot starts free");
        let ran = Cell::new(false);

        assert_eq!(
            with_picker(|| {
                ran.set(true);

                Ok(())
            }),
            Err(FILE_DIALOG_BUSY)
        );
        assert!(!ran.get());

        drop(holder);

        // While the save dialog is open, no binding picker can open.
        let other_blocked = Cell::new(false);

        assert_eq!(
            with_picker(|| {
                other_blocked.set(PickerSlot::acquire().is_none());

                Ok(())
            }),
            Ok(())
        );
        assert!(other_blocked.get());
        assert!(slot_is_free());
    }

    #[test]
    fn the_slot_is_released_on_every_way_out() {
        let _serial = PICKER_SLOT_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let f = fixture("b2b-slot-release");

        // Normal selection.
        let normal = with_picker(|| {
            choose_and_prepare_in(&f.state, &f.root, attempt(), || {
                Selection::Chosen(f.target.clone())
            })
        });

        assert!(normal.is_ok());
        assert!(slot_is_free());

        // User cancellation, an unusable selection, a validation refusal.
        for selection in [
            Selection::Cancelled,
            Selection::Unusable,
            Selection::Chosen(f.dest.join("copy.txt")),
            Selection::Chosen(f.vault.clone()),
        ] {
            assert!(
                with_picker(|| choose_and_prepare_in(&f.state, &f.root, attempt(), || selection))
                    .is_err()
            );
            assert!(slot_is_free());
        }

        // Session change and a dialog that ends in a lock.
        assert_eq!(
            with_picker(|| choose_and_prepare_in(&f.state, &f.root, attempt(), || {
                f.relock_and_unlock();

                Selection::Chosen(f.dest.join("late.lvault"))
            })),
            Err(SESSION_CHANGED)
        );
        assert!(slot_is_free());

        // A failure inside the guarded section.
        assert_eq!(with_picker::<()>(|| Err(NOT_PREPARED)), Err(NOT_PREPARED));
        assert!(slot_is_free());
    }

    // -- K, L. Confirmation ----------------------------------------------------

    #[test]
    fn only_an_explicit_confirmation_creates_the_encrypted_copy() {
        let f = fixture("b2b-confirm");

        let source = fs::read(&f.vault).unwrap();

        let first = f.prepare();

        // Preparing, twice, created nothing.
        f.assert_nothing_created();

        let second = f.prepare();

        f.assert_nothing_created();

        // The first review was replaced by the second: presenting it creates
        // nothing and spends the second one too.
        assert_eq!(f.confirm(&first.preparation_id), Err(PREPARATION_STALE));
        assert_eq!(f.confirm(&second.preparation_id), Err(PREPARATION_MISSING));
        f.assert_nothing_created();

        let current = f.prepare();

        assert_eq!(
            f.confirm(&current.preparation_id),
            Ok(CopyCreationOutcomeDto::CreatedAndVerified)
        );

        // Exactly the vault's authenticated bytes, in exactly the reviewed place.
        assert_eq!(f.dest_entries(), ["copy.lvault"]);
        assert_eq!(fs::read(&f.target).unwrap(), source);
        assert_eq!(fs::read(&f.vault).unwrap(), source);
    }

    #[test]
    fn wrong_and_repeated_preparation_ids_never_publish_again() {
        let f = fixture("b2b-ids");

        // A wrong id spends the preparation and creates nothing.
        for wrong in [SOME_ID, "not-an-id", ""] {
            let current = f.prepare();

            assert_eq!(f.confirm(wrong), Err(PREPARATION_STALE), "{wrong:?}");
            assert_eq!(f.confirm(&current.preparation_id), Err(PREPARATION_MISSING));

            f.assert_nothing_created();
        }

        // A successful confirmation is spent: a replay publishes nothing, even
        // after the copy is removed.
        let preparation = f.prepare();

        assert_eq!(
            f.confirm(&preparation.preparation_id),
            Ok(CopyCreationOutcomeDto::CreatedAndVerified)
        );

        fs::remove_file(&f.target).unwrap();

        assert_eq!(
            f.confirm(&preparation.preparation_id),
            Err(PREPARATION_MISSING)
        );
        assert_eq!(
            f.confirm(&preparation.preparation_id),
            Err(PREPARATION_MISSING)
        );

        f.assert_nothing_created();
    }

    #[test]
    fn an_expired_preparation_maps_to_a_stale_confirmation() {
        // The 120-second lifetime is enforced (and tested with an injected clock)
        // by the session; the command only has to report it as stale.
        assert_eq!(
            confirm_error(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::Expired
            )),
            PREPARATION_STALE
        );
    }

    #[test]
    fn confirmation_requires_a_live_session_and_the_preparation_dies_with_it() {
        let f = fixture("b2b-confirm-locked");

        let preparation = f.prepare();

        f.state.lock_vault().unwrap();

        assert_eq!(
            f.confirm(&preparation.preparation_id),
            Err(CommandError::from(AppStateError::VaultLocked))
        );

        f.state.unlock_vault(f.vault.clone(), password()).unwrap();

        assert_eq!(
            f.confirm(&preparation.preparation_id),
            Err(PREPARATION_MISSING)
        );
        f.assert_nothing_created();
    }

    #[test]
    fn a_changed_vault_is_refused_at_confirmation_and_creates_nothing() {
        let f = fixture("b2b-source-changed");

        let preparation = f.prepare();

        let mut bytes = fs::read(&f.vault).unwrap();

        bytes.push(b' ');

        fs::write(&f.vault, bytes).unwrap();

        assert_eq!(f.confirm(&preparation.preparation_id), Err(SOURCE_CHANGED));
        f.assert_nothing_created();
    }

    // -- O, N. Unbound afterwards, and the binding flows are unaffected ----------

    #[test]
    fn a_created_copy_stays_unbound_and_can_then_be_bound_by_the_unchanged_flow() {
        let f = fixture("b2b-unbound");

        f.create_copy();

        // No binding, no record, no trust state: only the file exists.
        f.assert_still_unbound();
        f.assert_nothing_pending();

        // Binding it is the separate, unchanged B1h flow.
        let target = SyncFileTarget::from_path(&f.target).unwrap();
        let bind = attempt();

        let token = f.state.begin_sync_binding_selection(bind).unwrap();

        let preview = f
            .state
            .prepare_initial_binding_for_session(token, bind, &f.root, &target)
            .unwrap()
            .unwrap();

        assert_eq!(
            f.state
                .confirm_initial_binding(&f.root, preview.preparation_id())
                .unwrap(),
            Ok(InitialBindingOutcome::BoundAndVerified)
        );

        // And a bound vault refuses to create another copy.
        assert_eq!(
            f.choose_path(&f.dest.join("second.lvault")),
            Err(BINDING_EXISTS)
        );
        assert_eq!(f.dest_entries(), ["copy.lvault"]);
    }

    #[test]
    fn old_copy_operations_cannot_void_a_newer_binding_approval() {
        let f = fixture("b2b-binding-unaffected");

        f.create_copy();

        // An old copy dialog that is still open.
        let old = attempt();

        let _token = f.state.begin_copy_creation_selection(old).unwrap();

        // The binding approval is prepared afterwards (this voids the copy flow's
        // own pending preparation, as every preparation does).
        let target = SyncFileTarget::from_path(&f.target).unwrap();
        let bind = attempt();

        let token = f.state.begin_sync_binding_selection(bind).unwrap();

        let preview = f
            .state
            .prepare_initial_binding_for_session(token, bind, &f.root, &target)
            .unwrap()
            .unwrap();

        // The old dialog is cancelled and its picker returns late.
        f.state.cancel_copy_creation_attempt(old).unwrap();

        assert_eq!(
            choose_and_prepare_in(&f.state, &f.root, old, || Selection::Chosen(
                f.dest.join("late.lvault")
            )),
            Err(ATTEMPT_SUPERSEDED)
        );

        // The binding approval is still exactly as prepared.
        assert_eq!(
            f.state
                .confirm_initial_binding(&f.root, preview.preparation_id())
                .unwrap(),
            Ok(InitialBindingOutcome::BoundAndVerified)
        );
        assert_eq!(f.dest_entries(), ["copy.lvault"]);
    }

    #[test]
    fn old_copy_operations_cannot_void_a_newer_reset_approval() {
        let f = fixture("b2b-reset-unaffected");

        f.create_copy();

        let target = SyncFileTarget::from_path(&f.target).unwrap();
        let bind = attempt();

        let token = f.state.begin_sync_binding_selection(bind).unwrap();

        let preview = f
            .state
            .prepare_initial_binding_for_session(token, bind, &f.root, &target)
            .unwrap()
            .unwrap();

        assert_eq!(
            f.state
                .confirm_initial_binding(&f.root, preview.preparation_id())
                .unwrap(),
            Ok(InitialBindingOutcome::BoundAndVerified)
        );

        // An old copy dialog, then a reset approval.
        let old = attempt();

        let _ = f.state.begin_copy_creation_selection(old).unwrap();

        let reset = f
            .state
            .prepare_binding_reset_for_attempt(attempt(), &f.root)
            .unwrap()
            .unwrap();

        f.state.cancel_copy_creation_attempt(old).unwrap();
        f.state.cancel_copy_creation_attempt(old).unwrap();

        assert_eq!(
            choose_and_prepare_in(&f.state, &f.root, old, || Selection::Chosen(
                f.dest.join("late.lvault")
            )),
            Err(ATTEMPT_SUPERSEDED)
        );

        assert_eq!(
            f.state
                .confirm_binding_reset(&f.root, reset.preparation_id())
                .unwrap(),
            Ok(BindingResetOutcome::ResetAndVerified)
        );

        assert_eq!(f.dest_entries(), ["copy.lvault"]);
    }

    #[test]
    fn a_binding_or_reset_preparation_voids_a_pending_copy_preparation() {
        let f = fixture("b2b-exclusion");

        // Binding refuses (the target is absent) but still voids the copy review.
        let preparation = f.prepare();
        let absent = SyncFileTarget::from_path(&f.dest.join("absent.lvault")).unwrap();

        let _ = f.state.prepare_initial_binding(&f.root, &absent).unwrap();

        assert_eq!(
            f.confirm(&preparation.preparation_id),
            Err(PREPARATION_MISSING)
        );

        // So does a reset (refused: nothing to reset).
        let preparation = f.prepare();

        let _ = f.state.prepare_binding_reset(&f.root).unwrap();

        assert_eq!(
            f.confirm(&preparation.preparation_id),
            Err(PREPARATION_MISSING)
        );

        // Cancelling the other flows does not cancel a copy.
        let preparation = f.prepare();

        f.state.cancel_initial_binding().unwrap();
        f.state.cancel_binding_reset().unwrap();

        assert_eq!(
            f.confirm(&preparation.preparation_id),
            Ok(CopyCreationOutcomeDto::CreatedAndVerified)
        );
    }
}
