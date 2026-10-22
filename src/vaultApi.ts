import { invoke } from "@tauri-apps/api/core";

import type {
  CategoryCommandInput,
  CategorySummary,
  DeleteVaultResult,
  GeneratedPassword,
  ClipboardCopyResult,
  EntryDetails,
  EntryCommandInput,
  EntrySummary,
  PasswordGeneratorInput,
  PasswordHealthReport,
  SiteIconSummary,
  SyncBindingOutcome,
  SyncBindingPreparation,
  SyncBindingResetOutcome,
  SyncBindingResetPreparation,
  SyncBindingStatus,
  TotpCode,
  VaultStatus,
} from "./types";

export function getVaultStatus(): Promise<VaultStatus> {
  return invoke<VaultStatus>("get_vault_status");
}

export function createVault(
  path: string,
  masterPassword: string,
): Promise<VaultStatus> {
  return invoke<VaultStatus>("create_vault", {
    path,
    masterPassword,
  });
}

export function unlockVault(
  path: string,
  masterPassword: string,
): Promise<VaultStatus> {
  return invoke<VaultStatus>("unlock_vault", {
    path,
    masterPassword,
  });
}

export function lockVault(): Promise<VaultStatus> {
  return invoke<VaultStatus>("lock_vault");
}
export function changeMasterPassword(
  currentMasterPassword: string,
  newMasterPassword: string,
): Promise<void> {
  return invoke<void>(
    "change_master_password",
    {
      currentMasterPassword,
      newMasterPassword,
    },
  );
}

export function createVaultBackup(
  path: string,
): Promise<void> {
  return invoke<void>(
    "create_vault_backup",
    { path },
  );
}

export function restoreVaultBackup(
  backupPath: string,
  destinationPath: string,
  masterPassword: string,
): Promise<void> {
  return invoke<void>(
    "restore_vault_backup",
    {
      backupPath,
      destinationPath,
      masterPassword,
    },
  );
}
export function listEntries(): Promise<EntrySummary[]> {
  return invoke<EntrySummary[]>("list_entries");
}

export function getEntry(
  id: string,
): Promise<EntryDetails> {
  return invoke<EntryDetails>("get_entry", { id });
}

export function listCategories(): Promise<CategorySummary[]> {
  return invoke<CategorySummary[]>("list_categories");
}

export function listSiteIcons(): Promise<SiteIconSummary[]> {
  return invoke<SiteIconSummary[]>("list_site_icons");
}

export function getPasswordHealth(): Promise<PasswordHealthReport> {
  return invoke<PasswordHealthReport>(
    "get_password_health",
  );
}

export function fetchSiteIcon(
  hostname: string,
): Promise<SiteIconSummary> {
  return invoke<SiteIconSummary>(
    "fetch_site_icon",
    { hostname },
  );
}

export function deleteSiteIcon(
  hostname: string,
): Promise<boolean> {
  return invoke<boolean>(
    "delete_site_icon",
    { hostname },
  );
}

export function deleteClosedVault(
  path: string,
): Promise<DeleteVaultResult> {
  return invoke<DeleteVaultResult>(
    "delete_closed_vault",
    { path },
  );
}
export function getRecentVaults(): Promise<string[]> {
  return invoke<string[]>("get_recent_vaults");
}

export function rememberRecentVault(
  path: string,
): Promise<string[]> {
  return invoke<string[]>(
    "remember_recent_vault",
    { path },
  );
}
export function generatePassword(
  input: PasswordGeneratorInput,
): Promise<GeneratedPassword> {
  return invoke<GeneratedPassword>(
    "generate_password",
    { input },
  );
}
export function copyEntryPassword(
  id: string,
): Promise<ClipboardCopyResult> {
  return invoke<ClipboardCopyResult>(
    "copy_entry_password",
    { id },
  );
}
export function getEntryTotpCode(
  id: string,
): Promise<TotpCode> {
  return invoke<TotpCode>(
    "get_entry_totp_code",
    { id },
  );
}

export function copyEntryTotp(
  id: string,
): Promise<ClipboardCopyResult> {
  return invoke<ClipboardCopyResult>(
    "copy_entry_totp",
    { id },
  );
}

export function createEntry(
  input: EntryCommandInput,
): Promise<EntrySummary> {
  return invoke<EntrySummary>(
    "create_entry",
    { input },
  );
}

export function updateEntry(
  id: string,
  input: EntryCommandInput,
): Promise<EntrySummary> {
  return invoke<EntrySummary>(
    "update_entry",
    {
      id,
      input,
    },
  );
}

export function deleteEntry(
  id: string,
): Promise<void> {
  return invoke<void>(
    "delete_entry",
    { id },
  );
}
export function createCategory(
  input: CategoryCommandInput,
): Promise<CategorySummary> {
  return invoke<CategorySummary>(
    "create_category",
    { input },
  );
}

export function updateCategory(
  id: string,
  input: CategoryCommandInput,
): Promise<CategorySummary> {
  return invoke<CategorySummary>(
    "update_category",
    {
      id,
      input,
    },
  );
}

export function deleteCategory(
  id: string,
): Promise<void> {
  return invoke<void>(
    "delete_category",
    { id },
  );
}
export function touchVaultActivity(): Promise<void> {
  return invoke<void>(
    "touch_vault_activity",
  );
}

/*
 * Stage 1U-4 B1j-2: sync-binding commands. The native file picker is
 * owned by Rust, so nothing here accepts a target path, and the two
 * confirm commands take only the opaque preparation id.
 */
export function getSyncBindingStatus(): Promise<SyncBindingStatus> {
  return invoke<SyncBindingStatus>(
    "get_sync_binding_status",
  );
}

/*
 * attemptId is a caller-chosen label for ONE file selection. It lets
 * Rust tell a closed dialog's late picker result or late cancel from
 * a newer attempt's. It is not a path, not a preparation id and not
 * consent: confirming still needs the Rust-issued preparationId.
 */
export function chooseAndPrepareSyncBinding(
  attemptId: string,
): Promise<SyncBindingPreparation> {
  return invoke<SyncBindingPreparation>(
    "choose_and_prepare_sync_binding",
    { attemptId },
  );
}

export function confirmSyncBinding(
  preparationId: string,
): Promise<SyncBindingOutcome> {
  return invoke<SyncBindingOutcome>(
    "confirm_sync_binding",
    { preparationId },
  );
}

export function cancelSyncBinding(
  attemptId: string,
): Promise<void> {
  return invoke<void>(
    "cancel_sync_binding",
    { attemptId },
  );
}

/*
 * As for chooseAndPrepareSyncBinding, attemptId is only a label that
 * lets Rust tell this reset attempt from an older one. It is not the
 * preparation id and not consent.
 */
export function prepareSyncBindingReset(
  attemptId: string,
): Promise<SyncBindingResetPreparation> {
  return invoke<SyncBindingResetPreparation>(
    "prepare_sync_binding_reset",
    { attemptId },
  );
}

export function confirmSyncBindingReset(
  preparationId: string,
): Promise<SyncBindingResetOutcome> {
  return invoke<SyncBindingResetOutcome>(
    "confirm_sync_binding_reset",
    { preparationId },
  );
}

export function cancelSyncBindingReset(
  attemptId: string,
): Promise<void> {
  return invoke<void>(
    "cancel_sync_binding_reset",
    { attemptId },
  );
}
