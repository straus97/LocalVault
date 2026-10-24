import type { ReactNode } from "react";

import type {
  CopyCreationErrorCode,
  CopyCreationPreparation,
} from "./types";

/*
 * Stage 1U-4 B2c: views and messages for creating a NEW encrypted
 * copy of the unlocked vault.
 *
 * This is not a second dialog. SyncBindingDialog owns the single modal,
 * its focus trap, its Escape handling and its request / attempt
 * lifecycle; this module only describes what each copy-creation phase
 * looks like and what each Rust error code means to a person.
 *
 * Creating a copy does NOT bind it, publish anything, push, pull or
 * synchronize. No text here may suggest that it does, that a cloud
 * provider accepted the file, or that the file survives an abrupt power
 * loss. Messages never repeat backend text, raw I/O detail, ids or
 * internal names; the only path shown is the one Rust itself returned
 * in the earlier preparation.
 */

export type CopyErrorKind =
  /* Rust reported a definite refusal or a definite "not created". */
  | "definite"
  /* The outcome on disk is not known; only the person can check it. */
  | "ambiguous"
  /* The vault is locked or expired; nothing more can be done here. */
  | "sessionEnded";

export interface CopyErrorView {
  title: string;
  message: string;
  kind: CopyErrorKind;
  /* Choosing a location again is a sensible next step. */
  canRestart: boolean;
  /* The folder must be checked by hand, so the path is shown. */
  targetPath: string | null;
}

export type CopyCreationState =
  | { phase: "copyIntro"; notice: string | null }
  | { phase: "copySelecting" }
  | {
      phase: "copyPreview";
      preparation: CopyCreationPreparation;
    }
  | {
      phase: "copyConfirm";
      preparation: CopyCreationPreparation;
    }
  /* Only the path survives the confirm call: the id is spent. */
  | { phase: "copyCreating"; targetPath: string }
  | { phase: "copyDone"; targetPath: string }
  | { phase: "copyError"; error: CopyErrorView };

/* "prepare" is read-only; "confirm" is the call that may write. */
export type CopyErrorStage = "prepare" | "confirm";

export const copyDialogCancelledNotice =
  "Место сохранения не выбрано. Ничего не создано.";

const approvalExpiryNote =
  "Подтверждение действует ограниченное время.";

interface CopySpec {
  title: string;
  message: string;
  kind: CopyErrorKind;
  canRestart: boolean;
  showPath: boolean;
}

const notCreatedTitle = "Копия не создана";
const unconfirmedTitle = "Результат не подтверждён";
const failedTitle = "Не удалось выполнить действие";

function refused(
  message: string,
  canRestart = false,
): CopySpec {
  return {
    title: notCreatedTitle,
    message,
    kind: "definite",
    canRestart,
    showPath: false,
  };
}

function ambiguous(message: string): CopySpec {
  return {
    title: unconfirmedTitle,
    message,
    kind: "ambiguous",
    canRestart: false,
    showPath: true,
  };
}

function sessionEnded(message: string): CopySpec {
  return {
    title: failedTitle,
    message,
    kind: "sessionEnded",
    canRestart: false,
    showPath: false,
  };
}

/*
 * A definite "not created" that still leaves something to check by
 * hand. There is deliberately no restart here.
 */
const stagingRemainsSpec: CopySpec = {
  title: notCreatedTitle,
  message:
    "Новая копия не создана, но временный зашифрованный файл мог остаться. Автоматическое удаление не выполняется. Проверьте выбранную папку.",
  kind: "definite",
  canRestart: false,
  showPath: true,
};

const unknownOutcomeMessage =
  "Не удалось достоверно определить, был ли создан файл. Не повторяйте создание автоматически. Проверьте выбранную папку.";

/*
 * One spec per code. Typing the record by CopyCreationErrorCode makes
 * the compiler fail if a code is added to types.ts without a message.
 */
const copyErrorSpecs: Record<
  CopyCreationErrorCode,
  CopySpec
> = {
  vaultLocked: sessionEnded(
    "Хранилище заблокировано. Разблокируйте его и повторите действие. Ничего не создано.",
  ),

  vaultSessionExpired: sessionEnded(
    "Хранилище автоматически заблокировано из-за бездействия. Ничего не создано.",
  ),

  stateUnavailable: refused(
    "Внутреннее состояние LocalVault временно недоступно. Ничего не создано.",
    true,
  ),

  invalidSystemClock: refused(
    "Системные часы недоступны. Ничего не создано.",
    true,
  ),

  vaultOperationFailed: refused(
    "Не удалось завершить операцию. Ничего не создано.",
    true,
  ),

  syncSessionChanged: refused(
    "Сессия хранилища изменилась, пока было открыто окно сохранения. Ничего не создано. Начните заново.",
    true,
  ),

  /* Normally a quiet no-op (see the dialog); mapped for completeness. */
  copyFileDialogCancelled: refused(
    copyDialogCancelledNotice,
    true,
  ),

  copyFileDialogBusy: refused(
    "Окно выбора файла уже открыто. Завершите выбор в нём или закройте его. Ничего не создано.",
    true,
  ),

  copyAttemptInvalid: refused(
    "Не удалось начать выбор места сохранения. Ничего не создано. Попробуйте ещё раз.",
    true,
  ),

  copyAttemptSuperseded: refused(
    "Этот выбор места сохранения уже не актуален. Ничего не создано. Начните заново.",
    true,
  ),

  copyTargetInvalid: refused(
    "Выбранное имя не подходит для файла LocalVault. Нужен новый файл с расширением .lvault. Ничего не создано.",
    true,
  ),

  copyTargetExists: refused(
    "По выбранному пути уже есть файл или папка. Существующие файлы не перезаписываются. Выберите новое имя. Ничего не создано и не изменено.",
    true,
  ),

  copyTargetIsVaultFile: refused(
    "Выбрано имя основного файла этого хранилища или одного из его служебных файлов. Выберите другое имя. Ничего не создано.",
    true,
  ),

  copyLocationUnsupported: refused(
    "Копию можно создать только в существующей папке на локальном диске NTFS. Выберите другое место. Ничего не создано.",
    true,
  ),

  copyTargetUnavailable: refused(
    "Выбранное расположение не удалось проверить. Выберите другую папку. Ничего не создано.",
    true,
  ),

  copySourceChanged: refused(
    "Файл хранилища изменился после проверки. Ничего не создано. Начните заново.",
    true,
  ),

  copySourceUnverifiable: refused(
    "Файл хранилища не удалось проверить как источник копии. Ничего не создано.",
    true,
  ),

  copyUnsavedChanges: refused(
    "В хранилище есть несохранённые изменения. Сохраните их и создайте копию снова. Ничего не создано.",
  ),

  copyLegacyVault: refused(
    "Это хранилище использует более старую версию файла, и его нельзя скопировать таким способом. Ничего не создано.",
  ),

  copyBindingExists: refused(
    "Для этого хранилища уже есть запись о связи, поэтому новая копия не создаётся. Проверьте состояние связи.",
  ),

  copyBindingStateCorrupt: refused(
    "Сохранённая запись о связи повреждена, не читается или не поддерживается. Копия не создана. Проверьте состояние связи.",
  ),

  copyNotPrepared: refused(
    "Не удалось подготовить создание копии. Ничего не создано.",
    true,
  ),

  copyPreparationMissing: refused(
    "Нет подготовленной копии, ожидающей подтверждения. Ничего не создано. Начните заново.",
    true,
  ),

  copyPreparationStale: refused(
    "Подтверждение устарело. Ничего не создано. Начните заново.",
    true,
  ),

  copyNotCreated: refused(
    "Новая копия не создана. Вы можете начать заново.",
    true,
  ),

  copyNotCreatedStagingRemains: stagingRemainsSpec,

  copyPublicationUnknown: ambiguous(unknownOutcomeMessage),

  copyCreatedUnverified: ambiguous(
    "Файл мог быть создан, но LocalVault не смог подтвердить его целостность. Не используйте его как проверенную копию.",
  ),
};

/*
 * Confirm-stage codes that mean "the call did not reach the session",
 * but that this UI will not present as a reason to retry: if anything
 * here is ever wrong, the safe assumption after the one call that may
 * write is that the folder must be checked.
 */
const confirmFallbackCodes: ReadonlySet<string> =
  new Set<CopyCreationErrorCode>([
    "stateUnavailable",
    "invalidSystemClock",
    "vaultOperationFailed",
  ]);

const unrecognizedPrepareSpec: CopySpec = refused(
  "Не удалось подготовить создание копии. Ничего не создано.",
  true,
);

const unrecognizedConfirmSpec: CopySpec = ambiguous(
  unknownOutcomeMessage,
);

/* Codes after which the parent must re-verify the vault session. */
export const copySessionRecheckCodes: ReadonlySet<string> =
  new Set<CopyCreationErrorCode>([
    "vaultLocked",
    "vaultSessionExpired",
    "syncSessionChanged",
  ]);

export function describeCopyError(
  code: string | null,
  stage: CopyErrorStage,
  targetPath: string | null,
): CopyErrorView {
  const known =
    code !== null &&
    Object.prototype.hasOwnProperty.call(
      copyErrorSpecs,
      code,
    );

  let spec: CopySpec;

  if (!known || code === null) {
    spec =
      stage === "confirm"
        ? unrecognizedConfirmSpec
        : unrecognizedPrepareSpec;
  } else if (
    stage === "confirm" &&
    confirmFallbackCodes.has(code)
  ) {
    spec = unrecognizedConfirmSpec;
  } else {
    spec = copyErrorSpecs[code as CopyCreationErrorCode];
  }

  return {
    title: spec.title,
    message: spec.message,
    kind: spec.kind,
    canRestart: spec.canRestart,
    targetPath: spec.showPath ? targetPath : null,
  };
}

export function FactRow({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="sync-binding-fact">
      <dt>{label}</dt>
      <dd title={value}>{value}</dd>
    </div>
  );
}

/*
 * What the dialog lets a copy-creation view do. Every callback is
 * implemented by the dialog, which owns the attempt, the request
 * generation and the in-flight guard.
 */
export interface CopyCreationActions {
  /* Leave the intro for the status view; nothing is owned yet. */
  onBackToStatus: () => void;
  /* Open the Rust-owned native save dialog for a fresh attempt. */
  onChoose: () => void;
  /* Void an unconfirmed preparation and return to the status view. */
  onCancelPreparation: () => void;
  onContinueToConfirm: (
    preparation: CopyCreationPreparation,
  ) => void;
  /* The one action that may create the file. */
  onConfirm: (
    preparation: CopyCreationPreparation,
  ) => void;
  onRestart: () => void;
  onShowStatus: () => void;
  onClose: () => void;
}

export function renderCopyCreationContent(
  state: CopyCreationState,
  actions: CopyCreationActions,
): { body: ReactNode; footer: ReactNode } {
  switch (state.phase) {
    case "copyIntro":
      return {
        body: (
          <>
            <h3 tabIndex={-1} data-phase-heading>
              Создание зашифрованной копии
            </h3>

            <p className="sync-binding-text">
              LocalVault создаст отдельную
              зашифрованную копию текущего
              хранилища. Это не создаёт связь с
              копией и не включает синхронизацию.
            </p>

            <div className="editor-security-note">
              Создание копии поддерживается только
              на локальных дисках NTFS.
            </div>

            {state.notice !== null && (
              <div
                className="editor-security-note"
                role="status"
              >
                {state.notice}
              </div>
            )}
          </>
        ),
        footer: (
          <>
            <button
              type="button"
              className="editor-secondary"
              onClick={actions.onBackToStatus}
            >
              Отмена
            </button>

            <button
              type="button"
              className="editor-primary"
              onClick={actions.onChoose}
            >
              Выбрать место сохранения…
            </button>
          </>
        ),
      };

    case "copySelecting":
      return {
        body: (
          <>
            <div
              className="crypto-progress-note"
              role="status"
              tabIndex={-1}
              data-phase-heading
            >
              <span
                className="crypto-spinner"
                aria-hidden="true"
              />
              Выберите место сохранения в окне
              системы. Затем LocalVault проверит
              расположение.
            </div>

            <p className="sync-binding-text">
              Если окно выбора не видно, проверьте
              панель задач. Выбор места сам по себе
              ничего не создаёт.
            </p>
          </>
        ),
        footer: (
          <button
            type="button"
            className="editor-secondary"
            onClick={actions.onClose}
          >
            Закрыть
          </button>
        ),
      };

    case "copyPreview":
      return {
        body: (
          <>
            <h3 tabIndex={-1} data-phase-heading>
              Копия готова к созданию
            </h3>

            <dl className="sync-binding-facts">
              <FactRow
                label="Хранилище:"
                value={state.preparation.vaultFileName}
              />

              <FactRow
                label="Новый файл:"
                value={state.preparation.targetPath}
              />
            </dl>

            <p className="sync-binding-text">
              Файл пока не создан. Для продолжения
              необходимо отдельное подтверждение.
            </p>

            <p className="sync-binding-text">
              Существующие файлы не будут
              перезаписаны.
            </p>

            <div className="editor-security-note">
              Созданная копия будет независимой.
              Если вы позднее измените основное
              хранилище, эта копия не обновится
              автоматически.
            </div>
          </>
        ),
        footer: (
          <>
            <button
              type="button"
              className="editor-secondary"
              onClick={actions.onCancelPreparation}
            >
              Отмена
            </button>

            <button
              type="button"
              className="editor-primary"
              onClick={() =>
                actions.onContinueToConfirm(
                  state.preparation,
                )
              }
            >
              Продолжить
            </button>
          </>
        ),
      };

    case "copyConfirm":
      return {
        body: (
          <>
            <h3 tabIndex={-1} data-phase-heading>
              Создать новую зашифрованную копию?
            </h3>

            <dl className="sync-binding-facts">
              <FactRow
                label="Новый файл:"
                value={state.preparation.targetPath}
              />
            </dl>

            <p className="sync-binding-text">
              LocalVault создаст новый файл по
              указанному пути. Существующие файлы
              не будут заменены.
            </p>

            <p className="sync-binding-text">
              После создания копия не будет
              автоматически привязана к хранилищу.
            </p>

            <div className="editor-security-note">
              {approvalExpiryNote}
            </div>
          </>
        ),
        footer: (
          <>
            <button
              type="button"
              className="editor-secondary"
              data-autofocus
              onClick={actions.onCancelPreparation}
            >
              Отмена
            </button>

            <button
              type="button"
              className="editor-primary"
              onClick={() =>
                actions.onConfirm(state.preparation)
              }
            >
              Создать копию
            </button>
          </>
        ),
      };

    case "copyCreating":
      return {
        body: (
          <div
            className="crypto-progress-note"
            role="status"
            tabIndex={-1}
            data-phase-heading
          >
            <span
              className="crypto-spinner"
              aria-hidden="true"
            />
            Создаём и проверяем зашифрованную
            копию…
          </div>
        ),
        footer: (
          <button
            type="button"
            className="editor-secondary"
            disabled
          >
            Закрыть
          </button>
        ),
      };

    case "copyDone":
      return {
        body: (
          <>
            <h3 tabIndex={-1} data-phase-heading>
              Зашифрованная копия создана
            </h3>

            <p className="sync-binding-text">
              LocalVault создал и проверил отдельный
              зашифрованный файл.
            </p>

            <dl className="sync-binding-facts">
              <FactRow
                label="Новый файл:"
                value={state.targetPath}
              />
            </dl>

            <p className="sync-binding-text">
              Связь с копией пока не настроена.
              Автоматическая синхронизация не
              включена.
            </p>

            <div className="editor-security-note">
              Копия содержит состояние хранилища на
              момент создания и не обновляется
              автоматически.
            </div>
          </>
        ),
        footer: (
          <>
            <button
              type="button"
              className="editor-secondary"
              onClick={actions.onShowStatus}
            >
              Показать состояние
            </button>

            <button
              type="button"
              className="editor-primary"
              onClick={actions.onClose}
            >
              Закрыть
            </button>
          </>
        ),
      };

    case "copyError": {
      const error = state.error;

      return {
        body: (
          <>
            <h3 tabIndex={-1} data-phase-heading>
              {error.title}
            </h3>

            <div
              className="editor-error sync-binding-inline-error"
              role="alert"
            >
              {error.message}
            </div>

            {error.targetPath !== null && (
              <dl className="sync-binding-facts">
                <FactRow
                  label="Выбранный путь:"
                  value={error.targetPath}
                />
              </dl>
            )}

            {error.kind === "ambiguous" && (
              <div className="editor-security-note">
                LocalVault не удаляет файлы и не
                связывает такой файл с хранилищем
                автоматически.
              </div>
            )}
          </>
        ),
        footer: (
          <>
            <button
              type="button"
              className={
                error.kind === "sessionEnded"
                  ? "editor-primary"
                  : "editor-secondary"
              }
              onClick={actions.onClose}
            >
              Закрыть
            </button>

            {error.kind !== "sessionEnded" && (
              <button
                type="button"
                className={
                  error.canRestart
                    ? "editor-secondary"
                    : "editor-primary"
                }
                onClick={actions.onShowStatus}
              >
                {error.kind === "ambiguous"
                  ? "Обновить состояние"
                  : "К состоянию связи"}
              </button>
            )}

            {error.canRestart && (
              <button
                type="button"
                className="editor-primary"
                onClick={actions.onRestart}
              >
                Начать заново
              </button>
            )}
          </>
        ),
      };
    }
  }
}
