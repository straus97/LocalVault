import { invoke } from "@tauri-apps/api/core";

import type {
  CategoryCommandInput,
  CategorySummary,
  GeneratedPassword,
  ClipboardCopyResult,
  EntryDetails,
  EntryCommandInput,
  EntrySummary,
  PasswordGeneratorInput,
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
