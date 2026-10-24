import {
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import type {
  CommandError,
  CopyCreationPreparation,
  SyncBindingErrorCode,
  SyncBindingPreparation,
  SyncBindingProblem,
  SyncBindingResetConsequence,
  SyncBindingResetPreparation,
  SyncBindingResetSubject,
  SyncBindingStatus,
  SyncBindingUntouched,
  SyncPendingPush,
} from "./types";

import {
  type CopyCreationState,
  copyDialogCancelledNotice,
  copySessionRecheckCodes,
  describeCopyError,
  FactRow,
  renderCopyCreationContent,
} from "./CopyCreationFlow";

import {
  cancelCopyCreation,
  cancelSyncBinding,
  cancelSyncBindingReset,
  chooseAndPrepareCopyCreation,
  chooseAndPrepareSyncBinding,
  confirmCopyCreation,
  confirmSyncBinding,
  confirmSyncBindingReset,
  getSyncBindingStatus,
  prepareSyncBindingReset,
} from "./vaultApi";

/*
 * Stage 1U-4 B1j-2: UI for the encrypted-copy binding.
 *
 * This dialog records or removes a LOCAL binding record only. It
 * does not publish, push, pull, adopt or synchronize anything, and
 * no text here may suggest that it does.
 *
 * Stage 1U-4 B2c adds a second, separate action to the same dialog:
 * creating a NEW encrypted copy (views in CopyCreationFlow.tsx).
 * Creating a copy never binds it; binding stays the B1j flow with
 * its own file selection and its own confirmation.
 *
 * Rust is authoritative for everything that matters: it owns the
 * native file picker, the session identity across the picker, the
 * 120-second approval lifetime, stale-preview detection and the
 * write itself. This component never supplies a path, never
 * retries a confirmation, never repairs a record, and keeps
 * preparation ids in React state only (never in browser storage,
 * logs or props).
 */

interface SyncBindingDialogProps {
  onClose: () => void;
  /*
   * Called when a command reports that the vault session is gone
   * or changed. The parent re-checks Rust and locks the UI.
   */
  onSessionEnded: () => void;
}

type ErrorContext = "status" | "bind" | "reset";

interface ErrorView {
  message: string;
  /* The outcome of a write is not known; only a fresh read helps. */
  ambiguous: boolean;
  /* The vault is locked or expired; nothing more can be done here. */
  sessionEnded: boolean;
}

type DialogState =
  | { phase: "loading" }
  | { phase: "status"; status: SyncBindingStatus }
  | { phase: "selecting" }
  | {
      phase: "preview";
      preparation: SyncBindingPreparation;
    }
  | {
      phase: "confirm";
      preparation: SyncBindingPreparation;
    }
  | { phase: "binding" }
  | {
      phase: "bound";
      status: SyncBindingStatus | null;
      refreshFailed: boolean;
    }
  | { phase: "resetPreparing" }
  | {
      phase: "resetPreview";
      preparation: SyncBindingResetPreparation;
    }
  | {
      phase: "resetConfirm";
      preparation: SyncBindingResetPreparation;
    }
  | { phase: "resetting" }
  | {
      phase: "resetDone";
      status: SyncBindingStatus | null;
      refreshFailed: boolean;
    }
  | { phase: "error"; error: ErrorView }
  | CopyCreationState;

type DialogPhase = DialogState["phase"];

/* A write or a preparation is in flight; the dialog cannot be left. */
const lockedPhases: ReadonlySet<DialogPhase> =
  new Set<DialogPhase>([
    "binding",
    "resetPreparing",
    "resetting",
    "copyCreating",
  ]);

/* Copy-creation phases holding a pending approval Cancel must void. */
const copyApprovalPhases: ReadonlySet<DialogPhase> =
  new Set<DialogPhase>([
    "copyPreview",
    "copyConfirm",
  ]);

/*
 * Phases in which this dialog owns a save-location attempt in Rust
 * (save dialog open, or its preview not yet confirmed). Leaving one
 * of them cancels that attempt, and only that attempt. copyCreating
 * is deliberately absent: the confirmed write is never "cancelled".
 */
const copyAttemptPhases: ReadonlySet<DialogPhase> =
  new Set<DialogPhase>([
    "copySelecting",
    "copyPreview",
    "copyConfirm",
  ]);

/* Phases holding a pending approval that Cancel must void. */
const bindApprovalPhases: ReadonlySet<DialogPhase> =
  new Set<DialogPhase>(["preview", "confirm"]);

/*
 * Phases in which this dialog owns a file-selection attempt in Rust
 * (picker open, or its preview not yet confirmed). Leaving one of them
 * cancels that attempt, and only that attempt.
 */
const bindAttemptPhases: ReadonlySet<DialogPhase> =
  new Set<DialogPhase>([
    "selecting",
    "preview",
    "confirm",
  ]);

const resetApprovalPhases: ReadonlySet<DialogPhase> =
  new Set<DialogPhase>([
    "resetPreview",
    "resetConfirm",
  ]);

/* Reset phases in which this dialog owns a reset attempt in Rust. */
const resetAttemptPhases: ReadonlySet<DialogPhase> =
  new Set<DialogPhase>([
    "resetPreparing",
    "resetPreview",
    "resetConfirm",
  ]);

/*
 * A fresh random label (UUID v4) for one file selection. Built from
 * getRandomValues so it does not depend on a secure context. It only
 * tells this attempt apart from older ones; it is not a secret, not
 * a preparation id and not consent.
 */
function newAttemptId(): string {
  const bytes = new Uint8Array(16);

  crypto.getRandomValues(bytes);

  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

const approvalExpiryNote =
  "Подтверждение действует ограниченное время.";

const staleBindingMessage =
  "Проверка устарела. Выберите копию и выполните проверку ещё раз.";

const staleResetMessage =
  "Подтверждение удаления устарело. Повторите проверку состояния связи.";

const ambiguousBindingMessage =
  "Не удалось подтвердить, сохранилась ли локальная связь. Она могла сохраниться. Повторять действие автоматически нельзя. Проверьте текущее состояние связи.";

const ambiguousResetMessage =
  "Не удалось достоверно подтвердить удаление локальной связи. Часть служебных данных могла быть удалена. Проверьте состояние.";

/*
 * One message per code. Typing the record by SyncBindingErrorCode
 * makes the compiler fail if a code is added to types.ts without a
 * message. A message never repeats a path, an id or backend text.
 */
const syncErrorMessages: Record<
  SyncBindingErrorCode,
  string | Record<ErrorContext, string>
> = {
  vaultLocked:
    "Хранилище заблокировано. Разблокируйте его и повторите действие.",

  vaultSessionExpired:
    "Хранилище автоматически заблокировано из-за бездействия.",

  stateUnavailable:
    "Внутреннее состояние LocalVault временно недоступно.",

  vaultOperationFailed: {
    status:
      "Не удалось прочитать состояние связи.",
    bind:
      "Не удалось завершить операцию. Проверьте текущее состояние связи.",
    reset:
      "Не удалось завершить операцию. Проверьте текущее состояние связи.",
  },

  syncFileDialogCancelled:
    "Файл не выбран. Ничего не изменено.",

  syncFileDialogBusy:
    "Окно выбора файла уже открыто. Завершите выбор в нём или закройте его.",

  syncAttemptInvalid:
    "Не удалось начать выбор файла. Выберите копию ещё раз.",

  syncAttemptSuperseded: {
    status:
      "Этот выбор файла уже не актуален. Выберите копию и выполните проверку ещё раз.",
    bind:
      "Этот выбор файла уже не актуален. Выберите копию и выполните проверку ещё раз.",
    reset: staleResetMessage,
  },

  syncSessionChanged:
    "Сессия хранилища изменилась, пока было открыто окно выбора файла. Выберите копию и выполните проверку ещё раз.",

  syncTargetInvalid:
    "Выбранный объект не является подходящим файлом LocalVault (.lvault).",

  syncPreparationMissing: {
    status: staleBindingMessage,
    bind: staleBindingMessage,
    reset: staleResetMessage,
  },

  syncPreparationStale: {
    status: staleBindingMessage,
    bind: staleBindingMessage,
    reset: staleResetMessage,
  },

  syncTargetAbsent:
    "Выбранный файл не найден.",

  syncTargetUnavailable:
    "Выбранный файл не удалось прочитать.",

  syncTargetDiffers:
    "Выбранный файл не является точной копией этого хранилища или изменился после проверки. Связь не создана.",

  syncTargetIsVault:
    "Выбран основной файл этого хранилища или один из его служебных файлов. Выберите отдельную зашифрованную копию.",

  syncFilesystemUnsupported:
    "Расположение выбранного файла не поддерживается или его не удалось проверить.",

  syncLocalVaultChanged: {
    status:
      "Файл хранилища изменился на диске. Повторите проверку состояния связи.",
    bind:
      "Файл хранилища изменился на диске. Выберите копию и выполните проверку ещё раз.",
    reset:
      "Файл хранилища изменился на диске. Повторите проверку состояния связи.",
  },

  syncBindingExists:
    "Для этого хранилища уже есть запись о связи. Проверьте текущее состояние связи.",

  syncBindingStateCorrupt:
    "Сохранённая запись о связи повреждена, не читается или не поддерживается. Проверьте состояние связи.",

  syncBindingFailed: {
    status:
      "Не удалось прочитать состояние связи.",
    bind:
      "Связь не создана. Проверьте состояние связи и повторите проверку.",
    reset:
      "Не удалось подготовить удаление локальной связи.",
  },

  syncBindingAmbiguous: ambiguousBindingMessage,

  syncNothingToReset:
    "Локальной записи о связи нет, удалять нечего.",

  syncResetEvidenceChanged:
    "Сохранённое состояние связи изменилось после проверки. Ничего не удалено. Повторите проверку состояния связи.",

  syncResetNotPermitted:
    "Сохранённое состояние связи нельзя безопасно сбросить. Ничего не удалено.",

  syncResetFailed:
    "Локальная связь не удалена.",

  syncResetAmbiguous: ambiguousResetMessage,
};

/* Codes after which the parent must re-verify the vault session. */
const sessionEndedCodes: ReadonlySet<string> =
  new Set<SyncBindingErrorCode>([
    "vaultLocked",
    "vaultSessionExpired",
  ]);

const sessionRecheckCodes: ReadonlySet<string> =
  new Set<SyncBindingErrorCode>([
    "vaultLocked",
    "vaultSessionExpired",
    "syncSessionChanged",
  ]);

const ambiguousCodes: ReadonlySet<string> =
  new Set<SyncBindingErrorCode>([
    "syncBindingAmbiguous",
    "syncResetAmbiguous",
  ]);

const genericErrorMessages: Record<
  ErrorContext,
  string
> = {
  status:
    "Не удалось прочитать состояние связи.",
  bind:
    "Не удалось завершить операцию. Проверьте текущее состояние связи.",
  reset:
    "Не удалось завершить операцию. Проверьте текущее состояние связи.",
};

function errorCodeOf(
  error: unknown,
): string | null {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof (error as CommandError).code ===
      "string"
  ) {
    return (error as CommandError).code;
  }

  return null;
}

function describeError(
  code: string | null,
  context: ErrorContext,
): ErrorView {
  const entry =
    code !== null &&
    Object.prototype.hasOwnProperty.call(
      syncErrorMessages,
      code,
    )
      ? syncErrorMessages[
          code as SyncBindingErrorCode
        ]
      : undefined;

  const message =
    entry === undefined
      ? genericErrorMessages[context]
      : typeof entry === "string"
        ? entry
        : entry[context];

  return {
    message,
    ambiguous:
      code !== null &&
      ambiguousCodes.has(code),
    sessionEnded:
      code !== null &&
      sessionEndedCodes.has(code),
  };
}

const problemTexts: Record<
  SyncBindingProblem,
  string
> = {
  corrupt:
    "Локальная запись о связи повреждена.",

  unsupportedVersion:
    "Локальная запись о связи создана неподдерживаемой версией LocalVault и не может быть прочитана.",

  unreadable:
    "Локальную запись о связи не удалось прочитать.",

  mismatch:
    "Локальная запись о связи не соответствует этому хранилищу или расположению его файла, поэтому ей нельзя доверять.",

  unavailable:
    "Состояние связи сейчас невозможно проверить. Например, файл хранилища мог измениться на диске.",
};

const resetSubjectTexts: Record<
  SyncBindingResetSubject,
  string
> = {
  verifiedBinding:
    "Проверенная связь с выбранной копией",

  mismatchedRecord:
    "Запись о связи, не соответствующая этому хранилищу",

  corruptRecord:
    "Повреждённая запись о связи",

  unsupportedRecord:
    "Запись о связи неподдерживаемой версии",

  interruptedWriteRemnants:
    "Остатки прерванной записи служебных данных",
};

const consequenceTexts: Record<
  SyncBindingResetConsequence,
  string
> = {
  removesLocalBindingRecord:
    "Будет удалена локальная запись о связи с копией.",

  removesTrustedSyncHistory:
    "Будет удалена служебная история обмена данными на этом компьютере.",

  mayDiscardPendingSyncIntent:
    "Может быть сброшена отметка о ещё не выполненном обмене данными.",

  keepsVaultAndBackup:
    "Хранилище и его резервная копия не изменяются.",

  keepsRemoteTarget:
    "Выбранная зашифрованная копия не удаляется и не изменяется.",

  doesNotProveRemoteContentAbsent:
    "Удаление записи не означает, что в выбранной копии нет данных.",

  doesNotEnablePublication:
    "Удаление записи не включает обмен данными между устройствами.",
};

const untouchedTexts: Record<
  SyncBindingUntouched,
  string
> = {
  primaryVault:
    "Основной файл хранилища (.lvault)",

  vaultBackup:
    "Внутренняя резервная копия хранилища",

  vaultLockFile:
    "Файл блокировки хранилища",

  selectedTargetFile:
    "Выбранная зашифрованная копия",
};

function pendingPushText(
  pendingPush: SyncPendingPush,
): string | null {
  switch (pendingPush) {
    case "pending":
      return "В служебных данных есть отметка о начатой и не завершённой отправке. Это только запись: никакая отправка сейчас не выполняется.";

    case "none":
      return "Отметок о незавершённой отправке нет.";

    default:
      return null;
  }
}

/* The reset is offered only where Rust can plausibly accept it. */
function resetOffered(
  status: SyncBindingStatus,
): boolean {
  switch (status.state.kind) {
    case "linked":
      return true;

    case "needsAttention":
      return (
        status.state.problem !== "unavailable"
      );

    default:
      return false;
  }
}

function PendingPushNote({
  pendingPush,
}: {
  pendingPush: SyncPendingPush;
}) {
  const text = pendingPushText(pendingPush);

  if (text === null) {
    return null;
  }

  return (
    <div className="editor-security-note">
      <strong>Служебная отметка:</strong>{" "}
      {text}
    </div>
  );
}

export default function SyncBindingDialog({
  onClose,
  onSessionEnded,
}: SyncBindingDialogProps) {
  const [state, setState] =
    useState<DialogState>({
      phase: "loading",
    });

  const dialogRef =
    useRef<HTMLElement | null>(null);

  const mountedRef = useRef(false);

  /*
   * Bumped by every action that starts a request and on unmount.
   * A result is applied only if it still belongs to the latest
   * request of a still-mounted dialog.
   */
  const generationRef = useRef(0);

  /* Synchronous guard against a second click before re-render. */
  const inFlightRef = useRef(false);

  const stateRef = useRef<DialogState>(state);

  /*
   * The attempt label of this dialog's current file selection, while
   * it owns one. Cancels carry it, so they only ever affect it.
   */
  const attemptRef = useRef<string | null>(null);

  /* The same for this dialog's reset attempt. */
  const resetAttemptRef =
    useRef<string | null>(null);

  /*
   * The same for this dialog's copy-creation attempt. It is a label
   * only: the preparation id never lives in a ref, and a cancel
   * always names this attempt, never a fresh id.
   */
  const copyAttemptRef =
    useRef<string | null>(null);

  /* Last status shown, so Cancel can return without a new read. */
  const lastStatusRef =
    useRef<SyncBindingStatus | null>(null);

  const openerRef =
    useRef<HTMLElement | null>(null);

  const onCloseRef = useRef(onClose);
  const onSessionEndedRef =
    useRef(onSessionEnded);

  useEffect(() => {
    stateRef.current = state;
    onCloseRef.current = onClose;
    onSessionEndedRef.current =
      onSessionEnded;
  });

  const isCurrent = useCallback(
    (request: number) =>
      mountedRef.current &&
      generationRef.current === request,
    [],
  );

  const fail = useCallback(
    (
      error: unknown,
      context: ErrorContext,
    ) => {
      const code = errorCodeOf(error);

      lastStatusRef.current = null;
      attemptRef.current = null;
      resetAttemptRef.current = null;
      copyAttemptRef.current = null;

      setState({
        phase: "error",
        error: describeError(code, context),
      });

      if (
        code !== null &&
        sessionRecheckCodes.has(code)
      ) {
        onSessionEndedRef.current();
      }
    },
    [],
  );

  /*
   * A failed copy-creation call. Rust has already spent or voided
   * the attempt on every error, so no cancel is sent from here.
   * targetPath is passed only for the confirm call, where an
   * unclear outcome needs a folder to check.
   */
  const failCopy = useCallback(
    (
      error: unknown,
      stage: "prepare" | "confirm",
      targetPath: string | null,
    ) => {
      const code = errorCodeOf(error);

      lastStatusRef.current = null;
      attemptRef.current = null;
      resetAttemptRef.current = null;
      copyAttemptRef.current = null;

      setState({
        phase: "copyError",
        error: describeCopyError(
          code,
          stage,
          targetPath,
        ),
      });

      if (
        code !== null &&
        copySessionRecheckCodes.has(code)
      ) {
        onSessionEndedRef.current();
      }
    },
    [],
  );

  const loadStatus = useCallback(async () => {
    const request = ++generationRef.current;

    setState({ phase: "loading" });

    try {
      const status =
        await getSyncBindingStatus();

      if (!isCurrent(request)) {
        return;
      }

      lastStatusRef.current = status;

      setState({ phase: "status", status });
    } catch (error) {
      if (isCurrent(request)) {
        fail(error, "status");
      }
    }
  }, [fail, isCurrent]);

  /* Mount: remember the opener, read status; unmount: clean up. */
  useEffect(() => {
    openerRef.current =
      document.activeElement instanceof
      HTMLElement
        ? document.activeElement
        : null;

    mountedRef.current = true;

    void loadStatus();

    return () => {
      mountedRef.current = false;
      generationRef.current += 1;

      /*
       * Leaving while a file selection is open or its preview is
       * unconfirmed (manual close, lock or expiry) cancels THIS
       * dialog's attempt: a picker that returns later then prepares
       * nothing, and a preview is voided. The cancel names the
       * attempt, so a newer dialog's approval is never touched. An
       * approval already being confirmed is never cancelled here.
       */
      const phase = stateRef.current.phase;
      const attemptId = attemptRef.current;
      const resetAttemptId =
        resetAttemptRef.current;
      const copyAttemptId =
        copyAttemptRef.current;

      attemptRef.current = null;
      resetAttemptRef.current = null;
      copyAttemptRef.current = null;

      if (
        attemptId !== null &&
        bindAttemptPhases.has(phase)
      ) {
        void cancelSyncBinding(attemptId).catch(
          () => undefined,
        );
      } else if (
        resetAttemptId !== null &&
        resetAttemptPhases.has(phase)
      ) {
        /*
         * Also covers a reset preparation still in flight: the cancel
         * names this attempt, so Rust refuses it if it arrives
         * later, and discards it if it already arrived. It never
         * touches a newer dialog's reset.
         */
        void cancelSyncBindingReset(
          resetAttemptId,
        ).catch(() => undefined);
      } else if (
        copyAttemptId !== null &&
        copyAttemptPhases.has(phase)
      ) {
        /*
         * Leaving while the save dialog is open or its preview is
         * unconfirmed cancels THIS dialog's copy attempt: a save
         * dialog that returns later prepares nothing, and a preview
         * is voided. A confirmation already running is never
         * cancelled, and no text claims that it could be.
         */
        void cancelCopyCreation(
          copyAttemptId,
        ).catch(() => undefined);
      }

      const opener = openerRef.current;

      if (opener && opener.isConnected) {
        opener.focus();
      }
    };
  }, [loadStatus]);

  /* Move focus to the new step so keyboard and screen readers follow. */
  useEffect(() => {
    const root = dialogRef.current;

    if (!root) {
      return;
    }

    const target =
      root.querySelector<HTMLElement>(
        "[data-autofocus]",
      ) ??
      root.querySelector<HTMLElement>(
        "[data-phase-heading]",
      ) ??
      root;

    target.focus();
  }, [state.phase]);

  function leaveWithoutAction() {
    if (
      lockedPhases.has(stateRef.current.phase)
    ) {
      return;
    }

    onCloseRef.current();
  }

  /* Escape: step back from an unconfirmed preview, else close. */
  const handleEscape = useCallback(() => {
    const phase = stateRef.current.phase;

    if (lockedPhases.has(phase)) {
      return;
    }

    if (bindApprovalPhases.has(phase)) {
      cancelBindingPreparation();
      return;
    }

    if (resetApprovalPhases.has(phase)) {
      cancelResetPreparation();
      return;
    }

    if (copyApprovalPhases.has(phase)) {
      cancelCopyPreparation();
      return;
    }

    /* The intro owns nothing yet: Escape steps back to the choice. */
    if (phase === "copyIntro") {
      returnToStatus();
      return;
    }

    onCloseRef.current();
  }, []);

  /* Keyboard: Escape, and a Tab loop that keeps focus in the dialog. */
  useEffect(() => {
    function handleKeyDown(
      event: KeyboardEvent,
    ) {
      if (event.key === "Escape") {
        event.preventDefault();
        handleEscape();
        return;
      }

      if (event.key !== "Tab") {
        return;
      }

      const root = dialogRef.current;

      if (!root) {
        return;
      }

      const focusable = Array.from(
        root.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      );

      if (focusable.length === 0) {
        event.preventDefault();
        root.focus();
        return;
      }

      const first = focusable[0];
      const last =
        focusable[focusable.length - 1];

      const active = document.activeElement;

      if (
        !(active instanceof HTMLElement) ||
        !root.contains(active) ||
        active === root
      ) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
        return;
      }

      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (
        !event.shiftKey &&
        active === last
      ) {
        event.preventDefault();
        first.focus();
      }
    }

    window.addEventListener(
      "keydown",
      handleKeyDown,
      true,
    );

    return () => {
      window.removeEventListener(
        "keydown",
        handleKeyDown,
        true,
      );
    };
  }, [handleEscape]);

  function returnToStatus() {
    const known = lastStatusRef.current;

    if (known) {
      generationRef.current += 1;
      setState({
        phase: "status",
        status: known,
      });
    } else {
      void loadStatus();
    }
  }

  /*
   * Cancel only voids an unconfirmed preview. It does not claim to
   * stop anything in flight: the final binding or reset always
   * needs its own explicit confirmation.
   */
  function cancelBindingPreparation() {
    if (inFlightRef.current) {
      return;
    }

    const attemptId = attemptRef.current;

    attemptRef.current = null;

    if (attemptId !== null) {
      void cancelSyncBinding(attemptId).catch(
        () => undefined,
      );
    }

    returnToStatus();
  }

  function cancelResetPreparation() {
    if (inFlightRef.current) {
      return;
    }

    const resetAttemptId =
      resetAttemptRef.current;

    resetAttemptRef.current = null;

    if (resetAttemptId !== null) {
      void cancelSyncBindingReset(
        resetAttemptId,
      ).catch(() => undefined);
    }

    returnToStatus();
  }

  /*
   * Cancel only voids an unconfirmed copy preview. It does not claim
   * to stop anything in flight: the file is created only by the
   * separate final confirmation.
   */
  function cancelCopyPreparation() {
    if (inFlightRef.current) {
      return;
    }

    const attemptId = copyAttemptRef.current;

    copyAttemptRef.current = null;

    if (attemptId !== null) {
      void cancelCopyCreation(attemptId).catch(
        () => undefined,
      );
    }

    returnToStatus();
  }

  function openCopyIntro() {
    if (inFlightRef.current) {
      return;
    }

    generationRef.current += 1;

    setState({
      phase: "copyIntro",
      notice: null,
    });
  }

  async function handleCopyChoose() {
    if (inFlightRef.current) {
      return;
    }

    inFlightRef.current = true;

    const request = ++generationRef.current;

    /* A fresh label for every attempt, reused only to cancel it. */
    const attemptId = newAttemptId();

    copyAttemptRef.current = attemptId;

    setState({ phase: "copySelecting" });

    try {
      /*
       * The save dialog is opened by Rust; no path is sent from
       * here, only this attempt's label.
       */
      const preparation =
        await chooseAndPrepareCopyCreation(
          attemptId,
        );

      if (!isCurrent(request)) {
        /*
         * Closed, locked or superseded while the save dialog was
         * open. Unmounting already cancelled this attempt; repeat
         * it for this attempt only (a no-op in Rust if it no longer
         * owns anything), so no usable approval is left behind.
         */
        void cancelCopyCreation(attemptId).catch(
          () => undefined,
        );
        return;
      }

      setState({
        phase: "copyPreview",
        preparation,
      });
    } catch (error) {
      if (!isCurrent(request)) {
        return;
      }

      if (
        errorCodeOf(error) ===
        "copyFileDialogCancelled"
      ) {
        /* Dismissing the save dialog is not a failure. */
        copyAttemptRef.current = null;

        setState({
          phase: "copyIntro",
          notice: copyDialogCancelledNotice,
        });
        return;
      }

      failCopy(error, "prepare", null);
    } finally {
      inFlightRef.current = false;
    }
  }

  async function handleCopyConfirm(
    preparation: CopyCreationPreparation,
  ) {
    if (inFlightRef.current) {
      return;
    }

    inFlightRef.current = true;

    const request = ++generationRef.current;

    /*
     * Only the opaque id leaves React state, once. It is spent by
     * this call whatever the result, and is never sent again.
     */
    const { preparationId, targetPath } =
      preparation;

    setState({ phase: "copyCreating", targetPath });

    try {
      await confirmCopyCreation(preparationId);

      copyAttemptRef.current = null;

      if (!isCurrent(request)) {
        return;
      }

      setState({ phase: "copyDone", targetPath });
    } catch (error) {
      if (isCurrent(request)) {
        failCopy(error, "confirm", targetPath);
      }
    } finally {
      inFlightRef.current = false;
    }
  }

  async function handleChoose() {
    if (inFlightRef.current) {
      return;
    }

    inFlightRef.current = true;

    const request = ++generationRef.current;

    const attemptId = newAttemptId();

    attemptRef.current = attemptId;

    setState({ phase: "selecting" });

    try {
      /*
       * The picker is opened by Rust; no path is sent from here,
       * only this attempt's label.
       */
      const preparation =
        await chooseAndPrepareSyncBinding(
          attemptId,
        );

      if (!isCurrent(request)) {
        /*
         * Closed, locked or superseded while the picker was open.
         * Unmounting already cancelled this attempt, so Rust refuses
         * such a late result; this repeats that cancel for the same
         * attempt only (a no-op if it is no longer the current one).
         */
        void cancelSyncBinding(attemptId).catch(
          () => undefined,
        );
        return;
      }

      setState({
        phase: "preview",
        preparation,
      });
    } catch (error) {
      if (!isCurrent(request)) {
        return;
      }

      if (
        errorCodeOf(error) ===
        "syncFileDialogCancelled"
      ) {
        /* Dismissing the picker is not a failure. */
        returnToStatus();
        return;
      }

      fail(error, "bind");
    } finally {
      inFlightRef.current = false;
    }
  }

  async function refreshAfterWrite(
    request: number,
    done: "bound" | "resetDone",
  ) {
    try {
      const status =
        await getSyncBindingStatus();

      if (!isCurrent(request)) {
        return;
      }

      lastStatusRef.current = status;

      setState({
        phase: done,
        status,
        refreshFailed: false,
      });
    } catch {
      if (isCurrent(request)) {
        lastStatusRef.current = null;

        setState({
          phase: done,
          status: null,
          refreshFailed: true,
        });
      }
    }
  }

  async function handleConfirmBinding(
    preparation: SyncBindingPreparation,
  ) {
    if (inFlightRef.current) {
      return;
    }

    inFlightRef.current = true;

    const request = ++generationRef.current;

    /* Only the opaque id leaves React state, once. */
    const preparationId =
      preparation.preparationId;

    setState({ phase: "binding" });

    try {
      await confirmSyncBinding(
        preparationId,
      );

      attemptRef.current = null;

      if (!isCurrent(request)) {
        return;
      }

      setState({
        phase: "bound",
        status: null,
        refreshFailed: false,
      });

      await refreshAfterWrite(
        request,
        "bound",
      );
    } catch (error) {
      if (isCurrent(request)) {
        fail(error, "bind");
      }
    } finally {
      inFlightRef.current = false;
    }
  }

  async function handlePrepareReset() {
    if (inFlightRef.current) {
      return;
    }

    inFlightRef.current = true;

    const request = ++generationRef.current;

    const resetAttemptId = newAttemptId();

    resetAttemptRef.current = resetAttemptId;

    setState({ phase: "resetPreparing" });

    try {
      const preparation =
        await prepareSyncBindingReset(
          resetAttemptId,
        );

      if (!isCurrent(request)) {
        /*
         * Closed or locked while preparing. Unmounting already
         * cancelled this attempt; repeat it for this attempt only
         * (a no-op in Rust if it no longer owns the pending reset),
         * so no usable approval is left behind.
         */
        void cancelSyncBindingReset(
          resetAttemptId,
        ).catch(() => undefined);
        return;
      }

      setState({
        phase: "resetPreview",
        preparation,
      });
    } catch (error) {
      if (isCurrent(request)) {
        fail(error, "reset");
      }
    } finally {
      inFlightRef.current = false;
    }
  }

  async function handleConfirmReset(
    preparation: SyncBindingResetPreparation,
  ) {
    if (inFlightRef.current) {
      return;
    }

    inFlightRef.current = true;

    const request = ++generationRef.current;

    const preparationId =
      preparation.preparationId;

    setState({ phase: "resetting" });

    try {
      await confirmSyncBindingReset(
        preparationId,
      );

      resetAttemptRef.current = null;

      if (!isCurrent(request)) {
        return;
      }

      setState({
        phase: "resetDone",
        status: null,
        refreshFailed: false,
      });

      await refreshAfterWrite(
        request,
        "resetDone",
      );
    } catch (error) {
      if (isCurrent(request)) {
        fail(error, "reset");
      }
    } finally {
      inFlightRef.current = false;
    }
  }

  function renderStatusBody(
    status: SyncBindingStatus,
  ): { body: ReactNode; footer: ReactNode } {
    const closeButton = (
      <button
        type="button"
        className="editor-secondary"
        onClick={leaveWithoutAction}
      >
        Закрыть
      </button>
    );

    const refreshButton = (
      <button
        type="button"
        className="editor-secondary"
        onClick={() => void loadStatus()}
      >
        Обновить состояние
      </button>
    );

    const resetZone = resetOffered(status) ? (
      <section
        className="sync-binding-manage"
        aria-labelledby="sync-binding-manage-title"
      >
        <h4 id="sync-binding-manage-title">
          Управление локальной связью
        </h4>

        <p>
          Удаляется только запись о связи на
          этом компьютере. Само хранилище и
          выбранная копия не удаляются.
        </p>

        <button
          type="button"
          className="editor-secondary sync-binding-danger"
          onClick={() => void handlePrepareReset()}
        >
          Удалить локальную связь
        </button>
      </section>
    ) : null;

    const pending = (
      <PendingPushNote
        pendingPush={status.pendingPush}
      />
    );

    switch (status.state.kind) {
      case "notConfigured":
        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                Связь не настроена
              </h3>

              <p className="sync-binding-text">
                Выберите действие. Ни одно из них
                не включает автоматическую
                синхронизацию.
              </p>

              <section
                className="sync-binding-option"
                aria-labelledby="sync-binding-option-bind-title"
              >
                <h4 id="sync-binding-option-bind-title">
                  Связать с существующей копией
                </h4>

                <p>
                  Выберите уже существующий
                  зашифрованный файл, чтобы проверить
                  его и сохранить локальную связь с
                  хранилищем.
                </p>

                <button
                  type="button"
                  className="editor-primary"
                  onClick={() => void handleChoose()}
                >
                  Выбрать копию…
                </button>
              </section>

              <section
                className="sync-binding-option"
                aria-labelledby="sync-binding-option-create-title"
              >
                <h4 id="sync-binding-option-create-title">
                  Создать новую зашифрованную копию
                </h4>

                <p>
                  Сохраните отдельную зашифрованную
                  копию этого хранилища в выбранной
                  папке. Существующие файлы не
                  перезаписываются.
                </p>

                <button
                  type="button"
                  className="editor-secondary"
                  onClick={openCopyIntro}
                >
                  Создать копию…
                </button>
              </section>

              <div className="editor-security-note">
                Обмен данными между устройствами
                пока не выполняется. Для связи с
                существующей копией выбранный файл
                должен быть отдельным файлом .lvault,
                идентичным этому хранилищу.
              </div>
            </>
          ),
          footer: closeButton,
        };

      case "linked":
        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                Копия выбрана
              </h3>

              <dl className="sync-binding-facts">
                <FactRow
                  label="Выбранная копия:"
                  value={status.state.targetPath}
                />
              </dl>

              <p className="sync-binding-text">
                LocalVault помнит расположение
                этой копии. Автоматическая
                синхронизация не включена, обмен
                данными между устройствами пока не
                выполняется.
              </p>

              {pending}
              {resetZone}
            </>
          ),
          footer: (
            <>
              {refreshButton}

              <button
                type="button"
                className="editor-primary"
                onClick={leaveWithoutAction}
              >
                Закрыть
              </button>
            </>
          ),
        };

      case "needsAttention":
        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                Требуется внимание
              </h3>

              <div
                className="editor-error sync-binding-inline-error"
                role="alert"
              >
                {problemTexts[status.state.problem]}
              </div>

              <p className="sync-binding-text">
                Сохранённое расположение копии не
                показывается, потому что его нельзя
                проверить. LocalVault ничего не
                исправляет автоматически.
              </p>

              {pending}
              {resetZone}
            </>
          ),
          footer: (
            <>
              {refreshButton}

              <button
                type="button"
                className="editor-primary"
                onClick={leaveWithoutAction}
              >
                Закрыть
              </button>
            </>
          ),
        };

      default:
        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                Состояние не распознано
              </h3>

              <p className="sync-binding-text">
                LocalVault не смог определить
                состояние связи. Попробуйте
                обновить его.
              </p>
            </>
          ),
          footer: (
            <>
              {closeButton}

              <button
                type="button"
                className="editor-primary"
                onClick={() => void loadStatus()}
              >
                Обновить состояние
              </button>
            </>
          ),
        };
    }
  }

  function renderResultStatus(
    status: SyncBindingStatus | null,
    refreshFailed: boolean,
  ): ReactNode {
    if (refreshFailed) {
      return (
        <div className="editor-security-note">
          Не удалось обновить сведения о
          состоянии связи. Нажмите «Обновить
          состояние».
        </div>
      );
    }

    if (status === null) {
      return (
        <div
          className="crypto-progress-note"
          role="status"
        >
          <span
            className="crypto-spinner"
            aria-hidden="true"
          />
          Проверяем сохранённое состояние…
        </div>
      );
    }

    switch (status.state.kind) {
      case "linked":
        return (
          <dl className="sync-binding-facts">
            <FactRow
              label="Проверенная копия:"
              value={status.state.targetPath}
            />
          </dl>
        );

      case "notConfigured":
        return (
          <div className="editor-security-note">
            Проверенное состояние: связь не
            настроена.
          </div>
        );

      default:
        return (
          <div className="editor-security-note">
            Проверенное состояние: требуется
            внимание. Откройте состояние связи.
          </div>
        );
    }
  }

  function renderContent(): {
    body: ReactNode;
    footer: ReactNode;
  } {
    switch (state.phase) {
      case "loading":
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
              Читаем состояние связи…
            </div>
          ),
          footer: (
            <button
              type="button"
              className="editor-secondary"
              onClick={leaveWithoutAction}
            >
              Закрыть
            </button>
          ),
        };

      case "status":
        return renderStatusBody(state.status);

      case "selecting":
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
                Выберите файл в окне системы.
                Затем LocalVault проверит копию.
              </div>

              <p className="sync-binding-text">
                Если окно выбора файла не видно,
                проверьте панель задач.
                Выбор файла сам по себе ничего не
                сохраняет.
              </p>
            </>
          ),
          footer: (
            <button
              type="button"
              className="editor-secondary"
              onClick={leaveWithoutAction}
            >
              Закрыть
            </button>
          ),
        };

      case "preview":
        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                Проверка пройдена
              </h3>

              <dl className="sync-binding-facts">
                <FactRow
                  label="Хранилище:"
                  value={
                    state.preparation.vaultFileName
                  }
                />

                <FactRow
                  label="Выбранная копия:"
                  value={
                    state.preparation.targetPath
                  }
                />
              </dl>

              <p className="sync-binding-text">
                Файлы соответствуют требованиям
                для первоначальной привязки.
              </p>

              <p className="sync-binding-text">
                После подтверждения LocalVault
                сохранит локальную запись о связи.
                Ни один из зашифрованных файлов не
                будет изменён.
              </p>

              <div className="editor-security-note">
                Обмен данными между устройствами
                пока не выполняется.{" "}
                {approvalExpiryNote}
              </div>
            </>
          ),
          footer: (
            <>
              <button
                type="button"
                className="editor-secondary"
                onClick={cancelBindingPreparation}
              >
                Отмена
              </button>

              <button
                type="button"
                className="editor-primary"
                onClick={() =>
                  setState({
                    phase: "confirm",
                    preparation: state.preparation,
                  })
                }
              >
                Продолжить
              </button>
            </>
          ),
        };

      case "confirm":
        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                Связать это хранилище с
                выбранной копией?
              </h3>

              <dl className="sync-binding-facts">
                <FactRow
                  label="Хранилище:"
                  value={
                    state.preparation.vaultFileName
                  }
                />

                <FactRow
                  label="Выбранная копия:"
                  value={
                    state.preparation.targetPath
                  }
                />
              </dl>

              <div className="editor-security-note">
                Будет сохранена только локальная
                запись о связи. {approvalExpiryNote}
              </div>
            </>
          ),
          footer: (
            <>
              <button
                type="button"
                className="editor-secondary"
                data-autofocus
                onClick={cancelBindingPreparation}
              >
                Отмена
              </button>

              <button
                type="button"
                className="editor-primary"
                onClick={() =>
                  void handleConfirmBinding(
                    state.preparation,
                  )
                }
              >
                Связать
              </button>
            </>
          ),
        };

      case "binding":
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
              Сохраняем и проверяем локальную
              связь…
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

      case "bound":
        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                Связь сохранена
              </h3>

              <p className="sync-binding-text">
                LocalVault запомнил выбранную копию.
                Автоматическая синхронизация не
                включена.
              </p>

              {renderResultStatus(
                state.status,
                state.refreshFailed,
              )}
            </>
          ),
          footer: (
            <>
              {state.refreshFailed && (
                <button
                  type="button"
                  className="editor-secondary"
                  onClick={() => void loadStatus()}
                >
                  Обновить состояние
                </button>
              )}

              <button
                type="button"
                className="editor-primary"
                onClick={leaveWithoutAction}
              >
                Закрыть
              </button>
            </>
          ),
        };

      case "resetPreparing":
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
              Проверяем сохранённое состояние
              связи…
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

      case "resetPreview": {
        const preparation = state.preparation;
        const pending = pendingPushText(
          preparation.pendingPush,
        );

        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                Что будет удалено
              </h3>

              <dl className="sync-binding-facts">
                <FactRow
                  label="Запись:"
                  value={
                    resetSubjectTexts[
                      preparation.subject
                    ]
                  }
                />

                {preparation.targetPath !==
                  null && (
                  <FactRow
                    label="Выбранная копия:"
                    value={preparation.targetPath}
                  />
                )}
              </dl>

              <h4 className="sync-binding-subtitle">
                Последствия
              </h4>

              <ul className="sync-binding-list">
                {preparation.consequences.map(
                  (consequence) => (
                    <li key={consequence}>
                      {consequenceTexts[
                        consequence
                      ] ?? consequence}
                    </li>
                  ),
                )}
              </ul>

              {pending !== null && (
                <div className="editor-security-note">
                  <strong>Служебная отметка:</strong>{" "}
                  {pending}
                </div>
              )}

              <h4 className="sync-binding-subtitle">
                Не затрагиваются
              </h4>

              <ul className="sync-binding-list">
                {preparation.untouched.map(
                  (item) => (
                    <li key={item}>
                      {untouchedTexts[item] ??
                        item}
                    </li>
                  ),
                )}
              </ul>

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
                onClick={cancelResetPreparation}
              >
                Отмена
              </button>

              <button
                type="button"
                className="editor-secondary sync-binding-danger"
                onClick={() =>
                  setState({
                    phase: "resetConfirm",
                    preparation,
                  })
                }
              >
                Продолжить
              </button>
            </>
          ),
        };
      }

      case "resetConfirm":
        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                Удалить локальную связь с копией?
              </h3>

              <p className="sync-binding-text">
                На этом компьютере будет удалена
                запись о связи и её служебная
                история. Это может сбросить сведения
                о ещё не выполненном обмене данными.
              </p>

              <p className="sync-binding-text">
                Само хранилище, его резервная копия,
                файл блокировки и выбранная
                зашифрованная копия не удаляются.
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
                onClick={cancelResetPreparation}
              >
                Отмена
              </button>

              <button
                type="button"
                className="editor-primary sync-binding-danger-solid"
                onClick={() =>
                  void handleConfirmReset(
                    state.preparation,
                  )
                }
              >
                Удалить локальную связь
              </button>
            </>
          ),
        };

      case "resetting":
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
              Удаляем локальную связь и проверяем
              результат…
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

      case "resetDone":
        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                Локальная связь удалена
              </h3>

              <p className="sync-binding-text">
                LocalVault удалил на этом компьютере
                запись о связи и её служебную
                историю. Хранилище, его резервная
                копия, файл блокировки и выбранная
                зашифрованная копия не удалялись.
              </p>

              {renderResultStatus(
                state.status,
                state.refreshFailed,
              )}
            </>
          ),
          footer: (
            <>
              <button
                type="button"
                className="editor-secondary"
                onClick={() => void loadStatus()}
              >
                Показать состояние
              </button>

              <button
                type="button"
                className="editor-primary"
                onClick={leaveWithoutAction}
              >
                Закрыть
              </button>
            </>
          ),
        };

      case "error":
        return {
          body: (
            <>
              <h3
                tabIndex={-1}
                data-phase-heading
              >
                {state.error.ambiguous
                  ? "Результат не подтверждён"
                  : "Не удалось выполнить действие"}
              </h3>

              <div
                className="editor-error sync-binding-inline-error"
                role="alert"
              >
                {state.error.message}
              </div>
            </>
          ),
          footer: (
            <>
              <button
                type="button"
                className={
                  state.error.sessionEnded
                    ? "editor-primary"
                    : "editor-secondary"
                }
                onClick={leaveWithoutAction}
              >
                Закрыть
              </button>

              {!state.error.sessionEnded && (
                <button
                  type="button"
                  className="editor-primary"
                  onClick={() => void loadStatus()}
                >
                  {state.error.ambiguous
                    ? "Обновить состояние"
                    : "К состоянию связи"}
                </button>
              )}
            </>
          ),
        };

      default:
        return renderCopyCreationContent(state, {
          onBackToStatus: returnToStatus,
          onChoose: () => void handleCopyChoose(),
          onCancelPreparation: cancelCopyPreparation,
          onContinueToConfirm: (preparation) =>
            setState({
              phase: "copyConfirm",
              preparation,
            }),
          onConfirm: (preparation) =>
            void handleCopyConfirm(preparation),
          onRestart: openCopyIntro,
          onShowStatus: () => void loadStatus(),
          onClose: leaveWithoutAction,
        });
    }
  }

  const content = renderContent();

  return (
    <div
      className="backup-modal-backdrop"
      role="presentation"
    >
      <section
        ref={dialogRef}
        className="backup-modal sync-binding-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="sync-binding-title"
        aria-busy={lockedPhases.has(state.phase)}
        tabIndex={-1}
      >
        <header className="backup-modal-header">
          <div>
            <span className="editor-eyebrow">
              Связь с копией
            </span>

            <h2 id="sync-binding-title">
              Связь с зашифрованной копией
            </h2>
          </div>

          <button
            type="button"
            className="editor-close"
            aria-label="Закрыть"
            disabled={lockedPhases.has(
              state.phase,
            )}
            onClick={leaveWithoutAction}
          >
            ×
          </button>
        </header>

        <div
          className="sync-binding-body"
          role="region"
          aria-labelledby="sync-binding-title"
          tabIndex={0}
        >
          {content.body}
        </div>

        <footer className="editor-footer">
          {content.footer}
        </footer>
      </section>
    </div>
  );
}
