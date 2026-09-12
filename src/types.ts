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
