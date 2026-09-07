export interface VaultStatus {
  unlocked: boolean;
  dirty: boolean;
}

export interface EntrySummary {
  id: string;
  title: string;
  url: string;
  username: string;
  categoryId: string | null;
  favorite: boolean;
  updatedAtMs: number;
}

export interface EntryDetails {
  id: string;
  title: string;
  url: string;
  username: string;
  password: string;
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

export interface CommandError {
  code: string;
  message: string;
}

export interface ClipboardCopyResult {
  clearAfterSeconds: number;
}
export type VaultFilter =
  | { type: "all" }
  | { type: "favorite" }
  | { type: "category"; categoryId: string };
export interface EntryCommandInput {
  title: string;
  url: string;
  username: string;
  password: string;
  notes: string;
  categoryId: string | null;
  tags: string[];
  favorite: boolean;
}
export interface CategoryCommandInput {
  name: string;
}
