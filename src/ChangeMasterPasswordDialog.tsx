import {
  type FormEvent,
  useState,
} from "react";

import type {
  CommandError,
} from "./types";

import {
  changeMasterPassword,
} from "./vaultApi";

interface ChangeMasterPasswordDialogProps {
  onCancel: () => void;
  onChanged: () => Promise<void> | void;
}

const credentialErrors: Record<string, string> = {
  currentMasterPasswordInvalid:
    "Текущий мастер-пароль введён неверно.",

  newMasterPasswordMatchesCurrent:
    "Новый мастер-пароль должен отличаться от текущего.",

  masterPasswordRequired:
    "Заполните поля мастер-пароля.",

  masterPasswordChangeFailed:
    "LocalVault не смог безопасно завершить смену мастер-пароля. Файлы хранилища не следует изменять вручную.",

  vaultChangedOnDisk:
    "Файл хранилища изменился на диске. LocalVault не будет менять мастер-пароль.",

  vaultSessionExpired:
    "Хранилище автоматически заблокировано из-за бездействия.",

  vaultLocked:
    "Хранилище уже заблокировано.",

  stateUnavailable:
    "Внутреннее состояние LocalVault временно недоступно.",
};

function friendlyCredentialError(
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
      credentialErrors[
        commandError.code
      ] ??
      "Не удалось изменить мастер-пароль."
    );
  }

  return "Не удалось изменить мастер-пароль.";
}

export default function ChangeMasterPasswordDialog({
  onCancel,
  onChanged,
}: ChangeMasterPasswordDialogProps) {
  const [busy, setBusy] =
    useState(false);

  const [errorMessage, setErrorMessage] =
    useState<string | null>(null);

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (busy) {
      return;
    }

    const form =
      event.currentTarget;

    const formData =
      new FormData(form);

    let currentPasswordForInvoke =
      formData.get(
        "currentMasterPassword",
      );

    let newPasswordForInvoke =
      formData.get(
        "newMasterPassword",
      );

    let confirmationForCheck =
      formData.get(
        "confirmMasterPassword",
      );

    currentPasswordForInvoke =
      typeof currentPasswordForInvoke === "string"
        ? currentPasswordForInvoke
        : "";

    newPasswordForInvoke =
      typeof newPasswordForInvoke === "string"
        ? newPasswordForInvoke
        : "";

    confirmationForCheck =
      typeof confirmationForCheck === "string"
        ? confirmationForCheck
        : "";

    formData.delete(
      "currentMasterPassword",
    );

    formData.delete(
      "newMasterPassword",
    );

    formData.delete(
      "confirmMasterPassword",
    );

    if (
      !currentPasswordForInvoke ||
      !newPasswordForInvoke ||
      !confirmationForCheck
    ) {
      form.reset();

      currentPasswordForInvoke = "";
      newPasswordForInvoke = "";
      confirmationForCheck = "";

      setErrorMessage(
        "Заполните все три поля.",
      );

      return;
    }

    if (
      newPasswordForInvoke !==
        confirmationForCheck
    ) {
      form.reset();

      currentPasswordForInvoke = "";
      newPasswordForInvoke = "";
      confirmationForCheck = "";

      setErrorMessage(
        "Новый мастер-пароль и подтверждение не совпадают.",
      );

      return;
    }

    if (
      currentPasswordForInvoke ===
        newPasswordForInvoke
    ) {
      form.reset();

      currentPasswordForInvoke = "";
      newPasswordForInvoke = "";
      confirmationForCheck = "";

      setErrorMessage(
        "Новый мастер-пароль должен отличаться от текущего.",
      );

      return;
    }

    confirmationForCheck = "";

    /*
     * Remove password values from the DOM before awaiting IPC.
     * JavaScript strings themselves cannot be reliably zeroized,
     * so LocalVault keeps their remaining lifetime as short as
     * practical and never stores them in React state.
     */
    form.reset();

    setBusy(true);
    setErrorMessage(null);

    try {
      await changeMasterPassword(
        currentPasswordForInvoke,
        newPasswordForInvoke,
      );

      await onChanged();
    } catch (error) {
      setErrorMessage(
        friendlyCredentialError(
          error,
        ),
      );
    } finally {
      currentPasswordForInvoke = "";
      newPasswordForInvoke = "";
      confirmationForCheck = "";

      setBusy(false);
    }
  }

  return (
    <div
      className="backup-modal-backdrop"
      role="presentation"
    >
      <section
        className="backup-modal change-password-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="change-master-password-title"
      >
        <header className="backup-modal-header">
          <div>
            <span className="editor-eyebrow">
              Master Password
            </span>

            <h2 id="change-master-password-title">
              Сменить мастер-пароль
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
          LocalVault проверит текущий пароль
          и создаст новую криптографическую
          обёртку для ключа сейфа. Записи
          останутся зашифрованными тем же
          Vault Key.
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
          <label className="editor-field">
            <span>
              Текущий мастер-пароль
            </span>

            <input
              autoFocus
              name="currentMasterPassword"
              type="password"
              required
              disabled={busy}
              autoComplete="off"
            />
          </label>

          <label className="editor-field">
            <span>
              Новый мастер-пароль
            </span>

            <input
              name="newMasterPassword"
              type="password"
              required
              disabled={busy}
              autoComplete="new-password"
            />
          </label>

          <label className="editor-field">
            <span>
              Повторите новый мастер-пароль
            </span>

            <input
              name="confirmMasterPassword"
              type="password"
              required
              disabled={busy}
              autoComplete="new-password"
            />
          </label>

          <div className="editor-security-note">
            <strong>
              Важно:
            </strong>{" "}
            резервные копии .lvbackup,
            созданные ДО смены пароля,
            не изменяются и по-прежнему
            требуют прежний мастер-пароль.
            После смены создайте новую
            резервную копию.
          </div>

          <div className="editor-security-note">
            Мастер-пароли не сохраняются.
            Основной .lvault и внутренний
            .lvault.backup после успешной
            смены будут использовать новый
            мастер-пароль.
          </div>

          {busy && (
            <div
              className="crypto-progress-note"
              role="status"
            >
              Проверяем мастер-пароль и обновляем криптографическую защиту.
              Это может занять несколько секунд — LocalVault продолжает работать.
            </div>
          )}
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
              disabled={busy}
            >
              {busy ? (
                <>
                  <span
                    className="crypto-spinner"
                    aria-hidden="true"
                  />
                  Проверяем и меняем…
                </>
              ) : (
                "Сменить мастер-пароль"
              )}
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}
