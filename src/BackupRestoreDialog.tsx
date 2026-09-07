import {
  type FormEvent,
  useState,
} from "react";

import {
  open as openDialog,
  save as saveDialog,
} from "@tauri-apps/plugin-dialog";

import type {
  CommandError,
} from "./types";

import {
  restoreVaultBackup,
} from "./vaultApi";

interface BackupRestoreDialogProps {
  onCancel: () => void;
  onRestored: (
    restoredPath: string,
  ) => Promise<void> | void;
}

const restoreErrors: Record<string, string> = {
  backupAlreadyExists:
    "По выбранному пути уже существует файл. LocalVault не будет его перезаписывать.",

  backupPathMatchesSource:
    "Резервная копия и восстановленное хранилище должны находиться по разным путям.",

  backupNotFound:
    "Файл резервной копии не найден.",

  invalidBackupPath:
    "Выбран некорректный путь.",

  backupAuthenticationFailed:
    "Не удалось подтвердить резервную копию. Проверьте мастер-пароль и целостность файла.",

  invalidBackup:
    "Файл повреждён или не является корректной резервной копией LocalVault.",

  masterPasswordRequired:
    "Введите мастер-пароль.",

  stateUnavailable:
    "Состояние LocalVault временно недоступно.",

  vaultAlreadyUnlocked:
    "Для восстановления сначала заблокируйте открытое хранилище.",
};

function friendlyRestoreError(
  error: unknown,
): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error
  ) {
    const commandError =
      error as CommandError;

    return (
      restoreErrors[
        commandError.code
      ] ??
      "Не удалось восстановить резервную копию."
    );
  }

  return "Не удалось восстановить резервную копию.";
}

function ensureVaultExtension(
  path: string,
): string {
  return path
    .toLocaleLowerCase()
    .endsWith(".lvault")
    ? path
    : `${path}.lvault`;
}

function backupStem(
  path: string,
): string {
  const normalized =
    path.replace(/\\/g, "/");

  const filename =
    normalized
      .split("/")
      .pop() ||
    "LocalVault";

  return filename
    .replace(
      /\.lvbackup$/i,
      "",
    )
    .replace(
      /\.lvault$/i,
      "",
    );
}

export default function BackupRestoreDialog({
  onCancel,
  onRestored,
}: BackupRestoreDialogProps) {
  const [backupPath, setBackupPath] =
    useState("");

  const [
    destinationPath,
    setDestinationPath,
  ] = useState("");

  const [busy, setBusy] =
    useState(false);

  const [errorMessage, setErrorMessage] =
    useState<string | null>(null);

  async function chooseBackup() {
    if (busy) {
      return;
    }

    setErrorMessage(null);
    setBusy(true);

    try {
      const path =
        await openDialog({
          title:
            "Выбрать резервную копию LocalVault",
          multiple: false,
          directory: false,
          filters: [
            {
              name:
                "LocalVault Backup",
              extensions: [
                "lvbackup",
              ],
            },
          ],
        });

      if (
        !path ||
        Array.isArray(path)
      ) {
        return;
      }

      setBackupPath(path);
      setDestinationPath("");
    } catch {
      setErrorMessage(
        "Не удалось открыть системный выбор файла.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function chooseDestination() {
    if (
      busy ||
      !backupPath
    ) {
      return;
    }

    setErrorMessage(null);
    setBusy(true);

    try {
      const path =
        await saveDialog({
          title:
            "Куда восстановить хранилище",
          defaultPath:
            `${
              backupStem(
                backupPath,
              )
            }-restored.lvault`,
          filters: [
            {
              name:
                "LocalVault",
              extensions: [
                "lvault",
              ],
            },
          ],
        });

      if (!path) {
        return;
      }

      setDestinationPath(
        ensureVaultExtension(
          path,
        ),
      );
    } catch {
      setErrorMessage(
        "Не удалось открыть системный выбор файла.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (busy) {
      return;
    }

    if (!backupPath) {
      setErrorMessage(
        "Сначала выберите файл .lvbackup.",
      );

      return;
    }

    if (!destinationPath) {
      setErrorMessage(
        "Выберите место для нового .lvault.",
      );

      return;
    }

    const form =
      event.currentTarget;

    const formData =
      new FormData(form);

    let passwordForInvoke =
      formData.get(
        "masterPassword",
      );

    passwordForInvoke =
      typeof passwordForInvoke === "string"
        ? passwordForInvoke
        : "";

    formData.delete(
      "masterPassword",
    );

    /*
     * Clear the DOM password field before awaiting IPC.
     * JavaScript strings cannot themselves be reliably
     * zeroized, so keep the remaining reference short-lived.
     */
    form.reset();

    if (!passwordForInvoke) {
      setErrorMessage(
        "Введите мастер-пароль.",
      );

      return;
    }

    setBusy(true);
    setErrorMessage(null);

    try {
      await restoreVaultBackup(
        backupPath,
        destinationPath,
        passwordForInvoke,
      );

      await onRestored(
        destinationPath,
      );
    } catch (error) {
      setErrorMessage(
        friendlyRestoreError(
          error,
        ),
      );
    } finally {
      passwordForInvoke = "";
      setBusy(false);
    }
  }

  return (
    <div
      className="backup-modal-backdrop"
      role="presentation"
    >
      <section
        className="backup-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="backup-restore-title"
      >
        <header className="backup-modal-header">
          <div>
            <span className="editor-eyebrow">
              Encrypted Restore
            </span>

            <h2 id="backup-restore-title">
              Восстановить из резервной копии
            </h2>
          </div>

          <button
            type="button"
            className="editor-close"
            aria-label="Закрыть"
            disabled={busy}
            onClick={onCancel}
          >
            ×
          </button>
        </header>

        <p className="backup-modal-description">
          LocalVault сначала проверит
          мастер-пароль и целостность
          зашифрованной копии, а затем
          создаст новый файл .lvault.
          Исходная копия не изменяется.
        </p>

        {errorMessage && (
          <div
            className="editor-error"
            role="alert"
          >
            {errorMessage}
          </div>
        )}

        <form
          className="backup-restore-form"
          autoComplete="off"
          onSubmit={(event) =>
            void handleSubmit(
              event,
            )
          }
        >
          <div className="backup-path-row">
            <div className="backup-path-copy">
              <strong>
                Резервная копия
              </strong>

              <small
                title={
                  backupPath ||
                  undefined
                }
              >
                {backupPath ||
                  "Файл .lvbackup не выбран"}
              </small>
            </div>

            <button
              type="button"
              className="editor-secondary"
              disabled={busy}
              onClick={() =>
                void chooseBackup()
              }
            >
              Выбрать
            </button>
          </div>

          <div className="backup-path-row">
            <div className="backup-path-copy">
              <strong>
                Новый файл
              </strong>

              <small
                title={
                  destinationPath ||
                  undefined
                }
              >
                {destinationPath ||
                  "Путь .lvault не выбран"}
              </small>
            </div>

            <button
              type="button"
              className="editor-secondary"
              disabled={
                busy ||
                !backupPath
              }
              onClick={() =>
                void chooseDestination()
              }
            >
              Выбрать
            </button>
          </div>

          <label className="editor-field">
            <span>
              Мастер-пароль копии
            </span>

            <input
              autoFocus
              name="masterPassword"
              type="password"
              required
              disabled={busy}
              autoComplete="off"
            />
          </label>

          <div className="editor-security-note">
            Мастер-пароль не сохраняется.
            Восстановление не перезаписывает
            существующие файлы и оставляет
            новый сейф заблокированным.
          </div>

          <footer className="editor-footer">
            <button
              type="button"
              className="editor-secondary"
              disabled={busy}
              onClick={onCancel}
            >
              Отмена
            </button>

            <button
              type="submit"
              className="editor-primary"
              disabled={
                busy ||
                !backupPath ||
                !destinationPath
              }
            >
              {busy
                ? "Проверяем…"
                : "Проверить и восстановить"}
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}
