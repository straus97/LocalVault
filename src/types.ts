export interface VaultStatus {
  unlocked: boolean;
  dirty: boolean;
}

export interface EntrySummary {
  id: string;
  title: string;
  profileName: string;
  url: string;
  username: string;
  totpEnabled: boolean;
  categoryId: string | null;
  favorite: boolean;
  updatedAtMs: number;
}

export interface EntryDetails {
  id: string;
  title: string;
  profileName: string;
  url: string;
  username: string;
  password: string;
  totpEnabled: boolean;
  notes: string;
  categoryId: string | null;
  tags: string[];
  favorite: boolean;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface CategorySummary {
  id: string;
  name: string;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface SiteIconSummary {
  hostname: string;
  pngBase64: string;
  updatedAtMs: number;
}

export type PasswordWeakReason =
  | "empty"
  | "tooShort"
  | "commonPassword"
  | "lowVariety"
  | "singleCharacterClass";

export interface PasswordHealthItem {
  entryId: string;
  title: string;
  profileName: string;
  url: string;
  username: string;
  weak: boolean;
  reused: boolean;
  weakReasons: PasswordWeakReason[];
}

export interface PasswordHealthReport {
  totalEntries: number;
  weakEntries: number;
  reusedEntries: number;
  affectedEntries: number;
  items: PasswordHealthItem[];
}

export interface CommandError {
  code: string;
  message: string;
}

export interface PasswordGeneratorInput {
  length: number;
  includeLowercase: boolean;
  includeUppercase: boolean;
  includeDigits: boolean;
  includeSymbols: boolean;
}

export interface GeneratedPassword {
  password: string;
}
export interface DeleteVaultResult {
  recentVaults: string[];
  internalBackupRemoved: boolean;
  lockFileRemoved: boolean;
}
export interface ClipboardCopyResult {
  clearAfterSeconds: number;
}

export interface TotpCode {
  code: string;
  expiresAtMs: number;
  periodSeconds: number;
  digits: number;
}

export type TotpUpdateMode =
  | "keep"
  | "replace"
  | "remove";

export type VaultFilter =
  | { type: "all" }
  | { type: "favorite" }
  | { type: "category"; categoryId: string };
export interface EntryCommandInput {
  title: string;
  profileName: string;
  url: string;
  username: string;
  password: string;
  totpUpdate: TotpUpdateMode;
  totpInput: string;
  notes: string;
  categoryId: string | null;
  tags: string[];
  favorite: boolean;
}
export interface CategoryCommandInput {
  name: string;
}

/*
 * Stage 1U-4 B1j-2: DTOs of the sync-binding command boundary
 * (src-tauri/src/commands/sync_binding.rs). Field and variant names
 * are the serde camelCase forms. Nothing here carries a fingerprint,
 * physical file id, key, salt or approval capability; a preparation id
 * is an opaque, single-use handle that is only passed back to the
 * matching confirm command.
 */

export type SyncPendingPush =
  | "none"
  | "pending"
  | "unavailable";

export type SyncBindingProblem =
  | "corrupt"
  | "unsupportedVersion"
  | "unreadable"
  | "mismatch"
  | "unavailable";

export type SyncBindingState =
  | { kind: "notConfigured" }
  | { kind: "linked"; targetPath: string }
  | {
      kind: "needsAttention";
      problem: SyncBindingProblem;
    };

export interface SyncBindingStatus {
  state: SyncBindingState;
  pendingPush: SyncPendingPush;
}

export interface SyncBindingPreparation {
  preparationId: string;
  vaultFileName: string;
  targetPath: string;
}

export type SyncBindingOutcome = "boundAndVerified";

export type SyncBindingResetSubject =
  | "verifiedBinding"
  | "mismatchedRecord"
  | "corruptRecord"
  | "unsupportedRecord"
  | "interruptedWriteRemnants";

export type SyncBindingResetConsequence =
  | "removesLocalBindingRecord"
  | "removesTrustedSyncHistory"
  | "mayDiscardPendingSyncIntent"
  | "keepsVaultAndBackup"
  | "keepsRemoteTarget"
  | "doesNotProveRemoteContentAbsent"
  | "doesNotEnablePublication";

export type SyncBindingUntouched =
  | "primaryVault"
  | "vaultBackup"
  | "vaultLockFile"
  | "selectedTargetFile";

export interface SyncBindingResetPreparation {
  preparationId: string;
  subject: SyncBindingResetSubject;
  targetPath: string | null;
  pendingPush: SyncPendingPush;
  consequences: SyncBindingResetConsequence[];
  untouched: SyncBindingUntouched[];
}

export type SyncBindingResetOutcome = "resetAndVerified";

/*
 * Every code the sync-binding commands can return: the fixed codes of
 * sync_binding.rs plus the outer vault-state codes of
 * CommandError::from(AppStateError) that can reach these commands.
 */
export type SyncBindingErrorCode =
  | "vaultLocked"
  | "vaultSessionExpired"
  | "stateUnavailable"
  | "vaultOperationFailed"
  | "syncFileDialogCancelled"
  | "syncFileDialogBusy"
  | "syncAttemptInvalid"
  | "syncAttemptSuperseded"
  | "syncSessionChanged"
  | "syncTargetInvalid"
  | "syncPreparationMissing"
  | "syncPreparationStale"
  | "syncTargetAbsent"
  | "syncTargetUnavailable"
  | "syncTargetDiffers"
  | "syncTargetIsVault"
  | "syncFilesystemUnsupported"
  | "syncLocalVaultChanged"
  | "syncBindingExists"
  | "syncBindingStateCorrupt"
  | "syncBindingFailed"
  | "syncBindingAmbiguous"
  | "syncNothingToReset"
  | "syncResetEvidenceChanged"
  | "syncResetNotPermitted"
  | "syncResetFailed"
  | "syncResetAmbiguous";
