import {
  type FormEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  open as openDialog,
  save as saveDialog,
} from "@tauri-apps/plugin-dialog";

import { listen } from "@tauri-apps/api/event";

import BackupRestoreDialog from "./BackupRestoreDialog";
import CategoryEditor from "./CategoryEditor";
import EntryEditor from "./EntryEditor";
import "./App.css";
import type {
  CategoryCommandInput,
  CategorySummary,
  CommandError,
  EntryCommandInput,
  EntryDetails,
  EntrySummary,
  VaultFilter,
  VaultStatus,
} from "./types";
import {
  createCategory,
  createVaultBackup,
  createEntry,
  createVault,
  deleteCategory,
  deleteClosedVault,
  deleteEntry,
  copyEntryPassword,
  getEntry,
  getRecentVaults,
  getVaultStatus,
  listCategories,
  listEntries,
  lockVault,
  rememberRecentVault,
  updateCategory,
  updateEntry,
  touchVaultActivity,
  unlockVault,
} from "./vaultApi";

type GateMode = "create" | "open";

function ensureBackupExtension(
  path: string,
): string {
  return path
    .toLocaleLowerCase()
    .endsWith(".lvbackup")
    ? path
    : `${path}.lvbackup`;
}

function backupDefaultName(
  vaultPath: string,
): string {
  const normalized =
    vaultPath.replace(/\\/g, "/");

  const filename =
    normalized
      .split("/")
      .pop() ||
    "LocalVault";

  const stem =
    filename.replace(
      /\.lvault$/i,
      "",
    );

  const stamp =
    new Date()
      .toISOString()
      .slice(0, 19)
      .replace(
        /[:T]/g,
        "-",
      );

  return `${stem}-${stamp}.lvbackup`;
}

const initialStatus: VaultStatus = {
  unlocked: false,
  dirty: false,
};

const friendlyErrors: Record<string, string> = {
  unlockFailed:
    "Не удалось разблокировать хранилище. Проверьте мастер-пароль.",
  vaultNotFound:
    "Файл хранилища не найден.",
  vaultAlreadyExists:
    "По этому пути уже существует хранилище.",
  vaultAlreadyUnlocked:
    "Хранилище уже разблокировано.",
  vaultInUse:
    "Это хранилище уже открыто в другом экземпляре LocalVault.",
  vaultChangedOnDisk:
    "Файл хранилища изменился на диске. LocalVault не будет перезаписывать его автоматически.",
  invalidVault:
    "Файл не является корректным хранилищем LocalVault или повреждён.",
  invalidVaultPath:
    "Выбран некорректный путь к хранилищу.",
  masterPasswordRequired:
    "Введите мастер-пароль.",
  backupAlreadyExists:
    "По выбранному пути уже существует резервная копия или файл хранилища. LocalVault не будет его перезаписывать.",
  backupPathMatchesSource:
    "Основной сейф и резервная копия должны находиться по разным путям.",
  backupNotFound:
    "Файл резервной копии не найден.",
  invalidBackupPath:
    "Выбран некорректный путь резервной копии.",
  backupAuthenticationFailed:
    "Не удалось подтвердить резервную копию.",
  invalidBackup:
    "Резервная копия повреждена или имеет неподдерживаемый формат.",
  stateUnavailable:
    "Внутреннее состояние LocalVault временно недоступно.",
  invalidSystemClock:
    "Не удалось получить корректное системное время.",
  vaultLockFailed:
    "Не удалось корректно заблокировать хранилище.",
  vaultOperationFailed:
    "Операция с хранилищем не выполнена.",
  vaultDeleteFailed:
    "Не удалось удалить файл хранилища. Проверьте права доступа и убедитесь, что файл не используется другой программой.",
  vaultSessionExpired:
    "Хранилище автоматически заблокировано из-за бездействия.",
  clipboardUnavailable:
    "Не удалось получить защищённый доступ к буферу обмена.",
  entryNotFound:
    "Выбранная запись больше не существует.",
  categoryNotFound:
    "Выбранная категория больше не существует.",
  categoryInUse:
    "Категорию нельзя удалить, пока она используется одной или несколькими записями.",
  invalidCategory:
    "Проверьте название категории.",
};

function normalizeCommandError(error: unknown): CommandError {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    "message" in error &&
    typeof (error as { code?: unknown }).code === "string" &&
    typeof (error as { message?: unknown }).message === "string"
  ) {
    return error as CommandError;
  }

  return {
    code: "unknown",
    message: "The operation could not be completed.",
  };
}

function friendlyError(error: unknown): string {
  const normalized = normalizeCommandError(error);

  return (
    friendlyErrors[normalized.code] ??
    "Не удалось выполнить операцию. Попробуйте ещё раз."
  );
}

function ensureVaultExtension(path: string): string {
  return path.toLowerCase().endsWith(".lvault")
    ? path
    : `${path}.lvault`;
}

function basename(path: string): string {
  const segments = path.split(/[\\/]/);
  return segments[segments.length - 1] || path;
}

function formatTimestamp(value: number): string {
  return new Intl.DateTimeFormat("ru-RU", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function App() {
  const [status, setStatus] =
    useState<VaultStatus>(initialStatus);

  const [booting, setBooting] = useState(true);
  const [busy, setBusy] = useState(false);
  const [errorMessage, setErrorMessage] =
    useState<string | null>(null);

  const [successMessage, setSuccessMessage] =
    useState<string | null>(null);

  const [
    restoreDialogOpen,
    setRestoreDialogOpen,
  ] = useState(false);

  const [gateMode, setGateMode] =
    useState<GateMode | null>(null);

  const [selectedPath, setSelectedPath] =
    useState("");

  const [currentVaultPath, setCurrentVaultPath] =
    useState("");

  const [recentVaultPaths, setRecentVaultPaths] =
    useState<string[]>([]);

const [entries, setEntries] =
    useState<EntrySummary[]>([]);

  const [categories, setCategories] =
    useState<CategorySummary[]>([]);

  const [filter, setFilter] =
    useState<VaultFilter>({ type: "all" });

  const [search, setSearch] = useState("");

  const [selectedEntryId, setSelectedEntryId] =
    useState<string | null>(null);

  const [selectedEntry, setSelectedEntry] =
    useState<EntryDetails | null>(null);

  const [detailsLoading, setDetailsLoading] =
    useState(false);

  const [passwordVisible, setPasswordVisible] =
    useState(false);
  const [copyBusy, setCopyBusy] =
    useState(false);

  const [copyMessage, setCopyMessage] =
    useState<string | null>(null);
const [
    categoryEditorMode,
    setCategoryEditorMode,
  ] = useState<
    "create" | "edit" | null
  >(null);

  const [
    editingCategory,
    setEditingCategory,
  ] = useState<CategorySummary | null>(
    null,
  );

  const [
    categoryMutationBusy,
    setCategoryMutationBusy,
  ] = useState(false);

  const [
    categoryMutationError,
    setCategoryMutationError,
  ] = useState<string | null>(null);
  const [entryEditorMode, setEntryEditorMode] =
    useState<"create" | "edit" | null>(
      null,
    );

  const [
    entryMutationBusy,
    setEntryMutationBusy,
  ] = useState(false);

  const [
    entryMutationError,
    setEntryMutationError,
  ] = useState<string | null>(null);

  const detailsRequest = useRef(0);

  async function loadUnlockedData() {
    const [nextEntries, nextCategories] =
      await Promise.all([
        listEntries(),
        listCategories(),
      ]);

    setEntries(nextEntries);
    setCategories(nextCategories);
  }

  function clearSecretView() {
    detailsRequest.current += 1;
    setSelectedEntry(null);
    setSelectedEntryId(null);
    setPasswordVisible(false);
    setDetailsLoading(false);
    setCopyBusy(false);
    setCopyMessage(null);
  }

  function clearUnlockedData() {
    setCategoryEditorMode(null);
    setEditingCategory(null);
    setCategoryMutationError(null);
    setEntryEditorMode(null);
    setEntryMutationError(null);
    clearSecretView();
    setEntries([]);
    setCategories([]);
    setSearch("");
    setFilter({ type: "all" });
  }

  function applyAutoLockedUi() {
    setStatus(initialStatus);

    clearUnlockedData();

    setBusy(false);
    setSuccessMessage(null);
    setRestoreDialogOpen(false);
    setDetailsLoading(false);
    setEntryMutationBusy(false);
    setCategoryMutationBusy(false);

    setGateMode(null);
    setSelectedPath("");


    setErrorMessage(
      "Хранилище автоматически заблокировано из-за бездействия.",
    );
  }
  useEffect(() => {
    let active = true;

    async function bootstrap() {
      try {
        const nextStatus =
          await getVaultStatus();

        let nextRecentVaultPaths: string[] =
          [];

        try {
          nextRecentVaultPaths =
            await getRecentVaults();
        } catch {
          if (active) {
            setErrorMessage(
              "Не удалось загрузить список недавних хранилищ. Сами файлы сейфов не затронуты.",
            );
          }
        }

        if (!active) {
          return;
        }

        setStatus(nextStatus);
        setRecentVaultPaths(
          nextRecentVaultPaths,
        );

        if (nextStatus.unlocked) {
          const [
            nextEntries,
            nextCategories,
          ] = await Promise.all([
            listEntries(),
            listCategories(),
          ]);

          if (!active) {
            return;
          }

          setEntries(nextEntries);
          setCategories(nextCategories);
        }
      } catch (error) {
        if (active) {
          setErrorMessage(
            friendlyError(error),
          );
        }
      } finally {
        if (active) {
          setBooting(false);
        }
      }
    }

    void bootstrap();

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    let unlisten:
      | (() => void)
      | undefined;

    void listen<void>(
      "vault-session-expired",
      () => {
        /*
         * A queued event can theoretically arrive just after
         * the user unlocks again. Re-check Rust before hiding
         * a newly active session.
         */
        void getVaultStatus()
          .then((nextStatus) => {
            if (!active) {
              return;
            }

            if (nextStatus.unlocked) {
              setStatus(nextStatus);
              return;
            }

            applyAutoLockedUi();
          })
          .catch(() => {
            if (active) {
              /*
               * If backend state cannot be verified, remove
               * decrypted WebView state rather than keeping
               * it visible.
               */
              applyAutoLockedUi();
            }
          });
      },
    )
      .then((nextUnlisten) => {
        if (active) {
          unlisten = nextUnlisten;
        } else {
          nextUnlisten();
        }
      })
      .catch(() => {
        if (!active) {
          return;
        }

        /*
         * Without the expiry event channel the UI cannot
         * reliably learn about backend auto-lock. Fail closed.
         */
        void lockVault()
          .catch(() => undefined)
          .finally(() => {
            if (active) {
              applyAutoLockedUi();
            }
          });
      });

    return () => {
      active = false;

      if (unlisten) {
        unlisten();
      }
    };
  }, []);

  useEffect(() => {
    if (!status.unlocked) {
      return;
    }

    let active = true;
    let heartbeatInFlight = false;

    const heartbeatIntervalMs =
      5_000;

    let lastHeartbeatMs =
      performance.now() -
      heartbeatIntervalMs;

    const verifyAfterHeartbeatFailure =
      () => {
        void getVaultStatus()
          .then((nextStatus) => {
            if (
              active &&
              !nextStatus.unlocked
            ) {
              applyAutoLockedUi();
            }
          })
          .catch(() => {
            if (active) {
              applyAutoLockedUi();
            }
          });
      };

    const handleUserActivity =
      () => {
        const now =
          performance.now();

        if (
          heartbeatInFlight ||
          now - lastHeartbeatMs <
            heartbeatIntervalMs
        ) {
          return;
        }

        lastHeartbeatMs = now;
        heartbeatInFlight = true;

        void touchVaultActivity()
          .catch(() => {
            /*
             * A heartbeat may be the operation which first
             * notices expiry. Verify immediately instead of
             * waiting for the watcher event.
             */
            verifyAfterHeartbeatFailure();
          })
          .finally(() => {
            if (active) {
              heartbeatInFlight =
                false;
            }
          });
      };

    const activityEvents = [
      "pointerdown",
      "keydown",
      "mousemove",
      "wheel",
      "focus",
    ] as const;

    for (
      const eventName
      of activityEvents
    ) {
      window.addEventListener(
        eventName,
        handleUserActivity,
        { passive: true },
      );
    }

    return () => {
      active = false;

      for (
        const eventName
        of activityEvents
      ) {
        window.removeEventListener(
          eventName,
          handleUserActivity,
        );
      }
    };
  }, [status.unlocked]);
  async function chooseVaultPath(
    mode: GateMode,
  ) {
    setErrorMessage(null);
    setBusy(true);

    try {
      if (mode === "create") {
        const path = await saveDialog({
          title:
            "Создать хранилище LocalVault",
          defaultPath:
            "LocalVault.lvault",
          filters: [
            {
              name: "LocalVault",
              extensions: ["lvault"],
            },
          ],
        });

        if (!path) {
          return;
        }

        setGateMode("create");
        setSelectedPath(
          ensureVaultExtension(path),
        );
      } else {
        const path = await openDialog({
          title:
            "Открыть хранилище LocalVault",
          multiple: false,
          directory: false,
          filters: [
            {
              name: "LocalVault",
              extensions: ["lvault"],
            },
          ],
        });

        if (
          !path ||
          Array.isArray(path)
        ) {
          return;
        }

        setGateMode("open");
        setSelectedPath(path);
      }

    } catch {
      setErrorMessage(
        "Не удалось открыть системный выбор файла.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function persistRecentVault(
    path: string,
  ) {
    try {
      const nextRecentVaultPaths =
        await rememberRecentVault(path);

      setRecentVaultPaths(
        nextRecentVaultPaths,
      );
    } catch {
      /*
       * Convenience metadata must never make a
       * successfully opened vault look like an
       * unlock failure.
       */
      setRecentVaultPaths(
        (current) => [
          path,
          ...current.filter(
            (candidate) =>
              candidate !== path,
          ),
        ].slice(0, 5),
      );

      setErrorMessage(
        "Хранилище открыто, но не удалось обновить список недавних хранилищ.",
      );
    }
  }

  async function handleDeleteRecentVault(
    path: string,
  ) {
    if (
      busy ||
      status.unlocked
    ) {
      return;
    }

    const name =
      basename(path);

    const confirmed =
      window.confirm(
        `Удалить хранилище «${name}»?

${path}

Будут удалены:
• основной файл .lvault;
• внутренняя предыдущая версия .lvault.backup, если она существует.

Созданные вами файлы .lvbackup НЕ удаляются.

Это действие нельзя отменить.`,
      );

    if (!confirmed) {
      return;
    }

    setBusy(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      const result =
        await deleteClosedVault(
          path,
        );

      setRecentVaultPaths(
        result.recentVaults,
      );

      if (
        result.internalBackupRemoved
      ) {
        setSuccessMessage(
          `Хранилище «${name}» удалено. Пользовательские .lvbackup не затронуты.`,
        );
      } else {
        setErrorMessage(
          `Основной сейф «${name}» удалён, но внутренний файл .lvault.backup не удалось удалить. Его нужно удалить вручную. Пользовательские .lvbackup не затронуты.`,
        );
      }
    } catch (error) {
      setErrorMessage(
        friendlyError(
          error,
        ),
      );
    } finally {
      setBusy(false);
    }
  }
  function openRecentVault(
    path: string,
  ) {
    setErrorMessage(null);
    setGateMode("open");
    setSelectedPath(path);
  }

  function cancelGateForm() {
    setGateMode(null);
    setSelectedPath("");
    setErrorMessage(null);
  }

  async function submitGate(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (!gateMode || !selectedPath) {
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

    let confirmationForCheck =
      formData.get(
        "confirmPassword",
      );

    passwordForInvoke =
      typeof passwordForInvoke === "string"
        ? passwordForInvoke
        : "";

    confirmationForCheck =
      typeof confirmationForCheck === "string"
        ? confirmationForCheck
        : "";

    /*
     * Drop FormData's references immediately. JavaScript
     * strings themselves cannot be reliably zeroized.
     */
    formData.delete(
      "masterPassword",
    );

    formData.delete(
      "confirmPassword",
    );

    if (!passwordForInvoke) {
      form.reset();

      confirmationForCheck = "";

      setErrorMessage(
        "Введите мастер-пароль.",
      );

      return;
    }

    if (
      gateMode === "create" &&
      passwordForInvoke !==
        confirmationForCheck
    ) {
      form.reset();

      passwordForInvoke = "";
      confirmationForCheck = "";

      setErrorMessage(
        "Мастер-пароли не совпадают. Введите их заново.",
      );

      return;
    }

    confirmationForCheck = "";

    /*
     * Clear DOM password fields before awaiting IPC.
     */
    form.reset();

    setBusy(true);
    setErrorMessage(null);

    try {
      const nextStatus =
        gateMode === "create"
          ? await createVault(
              selectedPath,
              passwordForInvoke,
            )
          : await unlockVault(
              selectedPath,
              passwordForInvoke,
            );

      setStatus(nextStatus);
      setCurrentVaultPath(
        selectedPath,
      );

      await persistRecentVault(
        selectedPath,
      );

      setGateMode(null);
      setSelectedPath("");

      await loadUnlockedData();
    } catch (error) {
      setErrorMessage(
        friendlyError(error),
      );
    } finally {
      /*
       * Best-effort shortening of LocalVault's JS reference.
       */
      passwordForInvoke = "";

      setBusy(false);
    }
  }
  async function selectEntry(
    entry: EntrySummary,
  ) {
    const request =
      ++detailsRequest.current;

    setSelectedEntryId(entry.id);
    setSelectedEntry(null);
    setPasswordVisible(false);
    setCopyMessage(null);
    setDetailsLoading(true);
    setErrorMessage(null);

    try {
      const details =
        await getEntry(entry.id);

      if (
        request === detailsRequest.current
      ) {
        setSelectedEntry(details);
      }
    } catch (error) {
      if (
        request === detailsRequest.current
      ) {
        setSelectedEntryId(null);
        setErrorMessage(
          friendlyError(error),
        );
      }
    } finally {
      if (
        request === detailsRequest.current
      ) {
        setDetailsLoading(false);
      }
    }
  }
  function openSelectedCategoryEditor() {
    if (filter.type !== "category") {
      return;
    }

    const category =
      categories.find(
        (candidate) =>
          candidate.id ===
          filter.categoryId,
      );

    if (!category) {
      setErrorMessage(
        "Выбранная категория больше не существует.",
      );
      return;
    }

    setEditingCategory(category);
    setCategoryMutationError(null);
    setCategoryEditorMode("edit");
  }

  async function handleCategorySubmit(
    name: string,
  ) {
    if (!categoryEditorMode) {
      return;
    }

    const input: CategoryCommandInput = {
      name,
    };

    if (
      categoryEditorMode === "edit" &&
      !editingCategory
    ) {
      setCategoryMutationError(
        "Не удалось определить редактируемую категорию.",
      );
      return;
    }

    setCategoryMutationBusy(true);
    setCategoryMutationError(null);

    try {
      const summary =
        categoryEditorMode === "edit" &&
        editingCategory
          ? await updateCategory(
              editingCategory.id,
              input,
            )
          : await createCategory(
              input,
            );

      const nextCategories =
        await listCategories();

      setCategories(nextCategories);

      setFilter({
        type: "category",
        categoryId: summary.id,
      });

      setEditingCategory(null);
      setCategoryEditorMode(null);
      setCategoryMutationError(null);
    } catch (error) {
      setCategoryMutationError(
        friendlyError(error),
      );
    } finally {
      setCategoryMutationBusy(false);
    }
  }

  async function handleDeleteCategory() {
    if (
      categoryEditorMode !== "edit" ||
      !editingCategory
    ) {
      return;
    }

    const categoryId =
      editingCategory.id;

    const confirmed =
      window.confirm(
        `Удалить категорию «${editingCategory.name}»?`,
      );

    if (!confirmed) {
      return;
    }

    setCategoryMutationBusy(true);
    setCategoryMutationError(null);

    try {
      await deleteCategory(
        categoryId,
      );

      const nextCategories =
        await listCategories();

      setCategories(nextCategories);

      if (
        filter.type === "category" &&
        filter.categoryId ===
          categoryId
      ) {
        setFilter({
          type: "all",
        });
      }

      setEditingCategory(null);
      setCategoryEditorMode(null);
    } catch (error) {
      setCategoryMutationError(
        friendlyError(error),
      );
    } finally {
      setCategoryMutationBusy(false);
    }
  }
  async function handleEntrySubmit(
    input: EntryCommandInput,
  ) {
    if (!entryEditorMode) {
      return;
    }

    if (
      entryEditorMode === "edit" &&
      !selectedEntry
    ) {
      setEntryMutationError(
        "Не удалось определить редактируемую запись.",
      );
      return;
    }

    setEntryMutationBusy(true);
    setEntryMutationError(null);

    try {
      const summary =
        entryEditorMode === "edit" &&
        selectedEntry
          ? await updateEntry(
              selectedEntry.id,
              input,
            )
          : await createEntry(input);

      const [
        nextEntries,
        nextDetails,
      ] = await Promise.all([
        listEntries(),
        getEntry(summary.id),
      ]);

      setEntries(nextEntries);
      setSelectedEntryId(
        summary.id,
      );
      setSelectedEntry(
        nextDetails,
      );
      setPasswordVisible(false);
      setEntryEditorMode(null);
      setEntryMutationError(null);
    } catch (error) {
      setEntryMutationError(
        friendlyError(error),
      );
    } finally {
      setEntryMutationBusy(false);
    }
  }

  async function handleCopyPassword() {
    if (
      !selectedEntry ||
      copyBusy
    ) {
      return;
    }

    setCopyBusy(true);
    setCopyMessage(null);

    try {
      const result =
        await copyEntryPassword(
          selectedEntry.id,
        );

      setCopyMessage(
        `Пароль скопирован. Буфер автоматически очистится через ${result.clearAfterSeconds} сек., если вы не скопируете что-то другое.`,
      );
    } catch (error) {
      setCopyMessage(
        friendlyError(error),
      );
    } finally {
      setCopyBusy(false);
    }
  }
  async function handleDeleteSelectedEntry() {
    if (!selectedEntry) {
      return;
    }

    const confirmed =
      window.confirm(
        `Удалить запись «${selectedEntry.title}»? Это действие нельзя отменить.`,
      );

    if (!confirmed) {
      return;
    }

    const entryId =
      selectedEntry.id;

    setEntryMutationBusy(true);
    setErrorMessage(null);

    try {
      await deleteEntry(entryId);

      const nextEntries =
        await listEntries();

      setEntries(nextEntries);
      clearSecretView();
    } catch (error) {
      setErrorMessage(
        friendlyError(error),
      );
    } finally {
      setEntryMutationBusy(false);
    }
  }

  async function handleCreateBackup() {
    if (
      busy ||
      !currentVaultPath
    ) {
      return;
    }

    setErrorMessage(null);
    setSuccessMessage(null);
    setBusy(true);

    try {
      const path =
        await saveDialog({
          title:
            "Создать резервную копию LocalVault",
          defaultPath:
            backupDefaultName(
              currentVaultPath,
            ),
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

      if (!path) {
        return;
      }

      const backupPath =
        ensureBackupExtension(
          path,
        );

      await createVaultBackup(
        backupPath,
      );

      setSuccessMessage(
        `Зашифрованная резервная копия создана: ${backupPath}`,
      );
    } catch (error) {
      setErrorMessage(
        friendlyError(
          error,
        ),
      );
    } finally {
      setBusy(false);
    }
  }
  async function handleLock() {
    clearSecretView();
    setBusy(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      const nextStatus =
        await lockVault();

      setStatus(nextStatus);
      clearUnlockedData();
      setGateMode(null);
      setSelectedPath("");
    } catch (error) {
      setErrorMessage(
        friendlyError(error),
      );
    } finally {
      setBusy(false);
    }
  }

  const categoryNames = useMemo(
    () =>
      new Map(
        categories.map((category) => [
          category.id,
          category.name,
        ]),
      ),
    [categories],
  );

  const visibleEntries = useMemo(() => {
    const query =
      search.trim().toLocaleLowerCase(
        "ru-RU",
      );

    return entries.filter((entry) => {
      if (
        filter.type === "favorite" &&
        !entry.favorite
      ) {
        return false;
      }

      if (
        filter.type === "category" &&
        entry.categoryId !==
          filter.categoryId
      ) {
        return false;
      }

      if (!query) {
        return true;
      }

      const haystack = [
        entry.title,
        entry.url,
        entry.username,
      ]
        .join("\n")
        .toLocaleLowerCase("ru-RU");

      return haystack.includes(query);
    });
  }, [entries, filter, search]);

  const favoriteCount = useMemo(
    () =>
      entries.filter(
        (entry) => entry.favorite,
      ).length,
    [entries],
  );

  if (booting) {
    return (
      <main className="boot-screen">
        <div className="brand-mark">
          <span />
        </div>
        <div className="boot-title">
          LocalVault
        </div>
        <div className="boot-caption">
          Проверяем состояние хранилища…
        </div>
      </main>
    );
  }

  if (!status.unlocked) {
    return (
      <main className={gateMode ? "gate-screen form-active" : "gate-screen"}>
        <section className="gate-card">
          <div className="gate-brand">
            <div
              className="brand-mark"
              aria-hidden="true"
            >
              <span />
            </div>

            <div>
              <div className="brand-name">
                LocalVault
              </div>
              <div className="brand-subtitle">
                Локальное зашифрованное
                хранилище
              </div>
            </div>
          </div>

          <div className="gate-copy">
            <div className="eyebrow">
              Ваши данные остаются локально
            </div>

            <h1>
              Пароли под вашим контролем
            </h1>

            <p>
              LocalVault хранит содержимое
              сейфа в зашифрованном файле
              на этом компьютере. Сервер и
              облачная учётная запись не
              требуются.
            </p>
          </div>

          {errorMessage && (
            <div
              className="error-banner"
              role="alert"
            >
              <span>{errorMessage}</span>
              <button
                type="button"
                aria-label="Закрыть сообщение"
                onClick={() =>
                  setErrorMessage(null)
                }
              >
                ×
              </button>
            </div>
          )}

          {successMessage && (
            <div
              className="gate-success"
              role="status"
            >
              <span>
                {successMessage}
              </span>

              <button
                type="button"
                aria-label="Закрыть сообщение"
                onClick={() =>
                  setSuccessMessage(null)
                }
              >
                ×
              </button>
            </div>
          )}
          {!gateMode ? (
            <div className="gate-actions">
              {recentVaultPaths.length > 0 && (
                <section
                  className="recent-vaults"
                  aria-label="Недавние хранилища"
                >
                  <div className="recent-vaults-label">
                    Недавние хранилища
                  </div>

                  {recentVaultPaths.map(
                    (path) => (
                      <div
                        className="recent-vault-item"
                        key={path}
                      >
                        <button
                          type="button"
                          className="recent-vault"
                          disabled={busy}
                          onClick={() =>
                            openRecentVault(path)
                          }
                        >
                          <span className="file-icon">
                            LV
                          </span>

                          <span className="recent-vault-copy">
                            <strong>
                              {basename(path)}
                            </strong>
                            <small title={path}>
                              {path}
                            </small>
                          </span>

                          <span
                            className="action-arrow"
                            aria-hidden="true"
                          >
                            →
                          </span>
                        </button>

                        <button
                          type="button"
                          className="recent-vault-delete"
                          aria-label={`Удалить хранилище ${basename(path)}`}
                          title="Удалить хранилище"
                          disabled={busy}
                          onClick={() =>
                            void handleDeleteRecentVault(
                              path,
                            )
                          }
                        >
                          ×
                        </button>
                      </div>
                    ),
                  )}
                </section>
              )}

              <button
                className="gate-action primary-card"
                type="button"
                disabled={busy}
                onClick={() =>
                  void chooseVaultPath(
                    "create",
                  )
                }
              >
                <span className="action-icon">
                  +
                </span>
                <span>
                  <strong>
                    Создать хранилище
                  </strong>
                  <small>
                    Новый зашифрованный
                    файл .lvault
                  </small>
                </span>
                <span className="action-arrow">
                  →
                </span>
              </button>

              <button
                className="gate-action"
                type="button"
                disabled={busy}
                onClick={() =>
                  void chooseVaultPath(
                    "open",
                  )
                }
              >
                <span className="action-icon">
                  ↗
                </span>
                <span>
                  <strong>
                    Открыть хранилище
                  </strong>
                  <small>
                    Выбрать существующий
                    файл .lvault
                  </small>
                </span>
                <span className="action-arrow">
                  →
                </span>
              </button>

              <button
                className="gate-action backup-card"
                type="button"
                disabled={busy}
                onClick={() => {
                  setErrorMessage(null);
                  setSuccessMessage(null);
                  setRestoreDialogOpen(true);
                }}
              >
                <span className="action-icon">
                  ↺
                </span>

                <span>
                  <strong>
                    Восстановить из копии
                  </strong>

                  <small>
                    Проверить .lvbackup и
                    создать новый .lvault
                  </small>
                </span>

                <span className="action-arrow">
                  →
                </span>
              </button>
            </div>
          ) : (
            <form
              key={`${gateMode}:${selectedPath}`}
              className="unlock-form"
              autoComplete="off"
              onSubmit={submitGate}
            >
              <div className="form-heading">
                <div>
                  <span className="eyebrow">
                    {gateMode === "create"
                      ? "Новое хранилище"
                      : "Разблокировка"}
                  </span>
                  <h2>
                    {gateMode === "create"
                      ? "Задайте мастер-пароль"
                      : "Введите мастер-пароль"}
                  </h2>
                </div>

                <button
                  type="button"
                  className="text-button"
                  disabled={busy}
                  onClick={cancelGateForm}
                >
                  Отмена
                </button>
              </div>

              <div className="chosen-file">
                <span className="file-icon">
                  LV
                </span>

                <span className="file-copy">
                  <strong>
                    {basename(selectedPath)}
                  </strong>
                  <small title={selectedPath}>
                    {selectedPath}
                  </small>
                </span>

                <button
                  type="button"
                  className="text-button"
                  disabled={busy}
                  onClick={() =>
                    void chooseVaultPath(
                      gateMode,
                    )
                  }
                >
                  Изменить
                </button>
              </div>

              <label className="field">
                <span>Мастер-пароль</span>
                <input
                  autoFocus
                  name="masterPassword"
                  autoComplete="off"
                  type="password"
                  required
                  disabled={busy}
                />
              </label>

              {gateMode === "create" && (
                <label className="field">
                  <span>
                    Повторите мастер-пароль
                  </span>
                  <input
                    name="confirmPassword"
                    autoComplete="off"
                    type="password"
                    required
                    disabled={busy}
                  />
                </label>
              )}

              <div className="password-note">
                Мастер-пароль не сохраняется.
                Если его потерять, LocalVault
                не сможет восстановить доступ к
                зашифрованному сейфу.
              </div>

              <button
                className="submit-button"
                type="submit"
                disabled={busy}
              >
                {busy
                  ? "Подождите…"
                  : gateMode === "create"
                    ? "Создать и открыть"
                    : "Разблокировать"}
              </button>
            </form>
          )}

          {restoreDialogOpen && (
            <BackupRestoreDialog
              onCancel={() =>
                setRestoreDialogOpen(false)
              }
              onRestored={async (
                restoredPath,
              ) => {
                setRestoreDialogOpen(false);

                await persistRecentVault(
                  restoredPath,
                );

                setSuccessMessage(
                  `Резервная копия проверена и восстановлена: ${restoredPath}. Новый сейф остаётся заблокированным.`,
                );
              }}
            />
          )}
          <div className="security-mode-note">
            <span className="security-dot" />
            Мастер-пароль не сохраняется.
            Данные остаются локально в
            зашифрованном файле хранилища.
          </div>
        </section>


      </main>
    );
  }

  return (
    <main className="vault-app">
      <header className="app-header">
        <div className="header-brand">
          <div
            className="brand-mark small"
            aria-hidden="true"
          >
            <span />
          </div>

          <div>
            <strong>LocalVault</strong>
            <small
              title={
                currentVaultPath ||
                "Открытое хранилище"
              }
            >
              {currentVaultPath
                ? basename(
                    currentVaultPath,
                  )
                : "Открытое хранилище"}
            </small>
          </div>
        </div>

        <div className="header-status">
          <span className="secure-status">
            <span className="secure-dot" />
            Хранилище разблокировано
          </span>

          <button
            type="button"
            className="backup-button"
            disabled={busy}
            onClick={() =>
              void handleCreateBackup()
            }
          >
            <span aria-hidden="true">
              ◫
            </span>
            Резервная копия
          </button>
          <button
            type="button"
            className="lock-button"
            disabled={busy}
            onClick={() =>
              void handleLock()
            }
          >
            <span aria-hidden="true">
              ◇
            </span>
            Заблокировать
          </button>
        </div>
      </header>

      {successMessage && (
        <div
          className="workspace-success"
          role="status"
        >
          <span>
            {successMessage}
          </span>

          <button
            type="button"
            aria-label="Закрыть сообщение"
            onClick={() =>
              setSuccessMessage(null)
            }
          >
            ×
          </button>
        </div>
      )}
      {errorMessage && (
        <div
          className="workspace-error"
          role="alert"
        >
          <span>{errorMessage}</span>
          <button
            type="button"
            onClick={() =>
              setErrorMessage(null)
            }
          >
            ×
          </button>
        </div>
      )}

      <div className="workspace">
        <aside className="sidebar">
          <nav
            className="sidebar-nav"
            aria-label="Фильтры хранилища"
          >
            <button
              type="button"
              className={
                filter.type === "all"
                  ? "nav-item active"
                  : "nav-item"
              }
              onClick={() =>
                setFilter({
                  type: "all",
                })
              }
            >
              <span className="nav-symbol">
                ▦
              </span>
              <span>Все записи</span>
              <small>{entries.length}</small>
            </button>

            <button
              type="button"
              className={
                filter.type === "favorite"
                  ? "nav-item active"
                  : "nav-item"
              }
              onClick={() =>
                setFilter({
                  type: "favorite",
                })
              }
            >
              <span className="nav-symbol">
                ☆
              </span>
              <span>Избранное</span>
              <small>{favoriteCount}</small>
            </button>
          </nav>

          <div className="sidebar-section">
            <div className="sidebar-label-row">
              <div className="sidebar-label">
                Категории
              </div>

              <button
                type="button"
                className="add-category-button"
                aria-label="Создать категорию"
                title="Создать категорию"
                disabled={
                  categoryMutationBusy
                }
                onClick={() => {
                  setEditingCategory(null);
                  setCategoryMutationError(
                    null,
                  );
                  setCategoryEditorMode(
                    "create",
                  );
                }}
              >
                +
              </button>
            </div>

            {categories.length === 0 ? (
              <div className="sidebar-empty">
                Категорий пока нет
              </div>
            ) : (
              <div className="category-list">
                {categories.map(
                  (category) => {
                    const count =
                      entries.filter(
                        (entry) =>
                          entry.categoryId ===
                          category.id,
                      ).length;

                    const active =
                      filter.type ===
                        "category" &&
                      filter.categoryId ===
                        category.id;

                    return (
                      <button
                        type="button"
                        className={
                          active
                            ? "category-item active"
                            : "category-item"
                        }
                        key={category.id}
                        onClick={() =>
                          setFilter({
                            type:
                              "category",
                            categoryId:
                              category.id,
                          })
                        }
                      >
                        <span className="category-dot" />
                        <span>
                          {category.name}
                        </span>
                        <small>{count}</small>
                      </button>
                    );
                  },
                )}
              </div>
            )}
          </div>
          {filter.type === "category" && (
            <button
              type="button"
              className="manage-category-button"
              disabled={
                categoryMutationBusy
              }
              onClick={
                openSelectedCategoryEditor
              }
            >
              <span aria-hidden="true">
                ···
              </span>
              Управлять категорией
            </button>
          )}

          <div className="sidebar-footer">
            <div className="security-chip">
              LOCAL ONLY
            </div>
            <p>
              Автоблокировка: 60 секунд.
              Защищённый буфер: 30 секунд.
              Генерация паролей выполняется через
              криптографический источник ОС.
            </p>
          </div>
        </aside>

        <section className="entry-column">
          <div className="entry-column-header">
            <div>
              <span className="column-eyebrow">
                Хранилище
              </span>
              <h2>
                {filter.type === "all"
                  ? "Все записи"
                  : filter.type ===
                      "favorite"
                    ? "Избранное"
                    : categoryNames.get(
                          filter.categoryId,
                        ) ??
                      "Категория"}
              </h2>
            </div>

            <div className="entry-header-actions">
              <span className="entry-count">
                {visibleEntries.length}
              </span>

              <button
                type="button"
                className="new-entry-button"
                disabled={entryMutationBusy}
                onClick={() => {
                  setEntryMutationError(null);
                  setEntryEditorMode(
                    "create",
                  );
                }}
              >
                <span aria-hidden="true">
                  +
                </span>
                Новая запись
              </button>
            </div>
          </div>

          <div className="search-box">
            <span aria-hidden="true">
              ⌕
            </span>
            <input
              value={search}
              onChange={(event) =>
                setSearch(
                  event.currentTarget.value,
                )
              }
              placeholder="Поиск по названию, сайту или логину"
              spellCheck={false}
            />
          </div>

          <div className="entry-list">
            {visibleEntries.length === 0 ? (
              <div className="empty-list">
                <div className="empty-icon">
                  ◫
                </div>
                <strong>
                  Записей не найдено
                </strong>
                <span>
                  Здесь появятся сохранённые
                  учётные записи.
                </span>
              </div>
            ) : (
              visibleEntries.map(
                (entry) => (
                  <button
                    type="button"
                    className={
                      selectedEntryId ===
                      entry.id
                        ? "entry-row active"
                        : "entry-row"
                    }
                    key={entry.id}
                    onClick={() =>
                      void selectEntry(
                        entry,
                      )
                    }
                  >
                    <span className="entry-avatar">
                      {entry.title
                        .trim()
                        .slice(0, 1)
                        .toLocaleUpperCase(
                          "ru-RU",
                        ) || "•"}
                    </span>

                    <span className="entry-row-copy">
                      <strong>
                        {entry.title}
                      </strong>
                      <small>
                        {entry.username ||
                          entry.url ||
                          "Без дополнительной информации"}
                      </small>
                    </span>

                    {entry.favorite && (
                      <span
                        className="favorite-star"
                        aria-label="Избранное"
                      >
                        ★
                      </span>
                    )}
                  </button>
                ),
              )
            )}
          </div>
        </section>

        <section className="detail-column">
          {detailsLoading ? (
            <div className="detail-placeholder">
              <div className="detail-spinner" />
              <strong>
                Загружаем запись…
              </strong>
            </div>
          ) : !selectedEntry ? (
            <div className="detail-placeholder">
              <div className="detail-lock">
                <span />
              </div>
              <strong>
                Выберите запись
              </strong>
              <p>
                Пароль и заметки загружаются
                из Rust только для явно
                выбранной записи.
              </p>
            </div>
          ) : (
            <div className="entry-detail">
              <div className="detail-toolbar">
                <button
                  type="button"
                  className="detail-action"
                  disabled={entryMutationBusy}
                  onClick={() => {
                    setEntryMutationError(null);
                    setEntryEditorMode(
                      "edit",
                    );
                  }}
                >
                  Изменить
                </button>

                <button
                  type="button"
                  className="detail-action danger"
                  disabled={entryMutationBusy}
                  onClick={() =>
                    void handleDeleteSelectedEntry()
                  }
                >
                  Удалить
                </button>
              </div>
              <div className="detail-heading">
                <div className="detail-avatar">
                  {selectedEntry.title
                    .trim()
                    .slice(0, 1)
                    .toLocaleUpperCase(
                      "ru-RU",
                    ) || "•"}
                </div>

                <div>
                  <h2>
                    {selectedEntry.title}
                  </h2>
                  <span>
                    {selectedEntry.categoryId
                      ? categoryNames.get(
                          selectedEntry.categoryId,
                        ) ??
                        "Без категории"
                      : "Без категории"}
                  </span>
                </div>

                {selectedEntry.favorite && (
                  <div
                    className="detail-favorite"
                    title="Избранное"
                  >
                    ★
                  </div>
                )}
              </div>

              <div className="detail-section">
                <div className="detail-label">
                  Логин
                </div>
                <div className="detail-value">
                  {selectedEntry.username ||
                    "—"}
                </div>
              </div>

              <div className="detail-section">
                <div className="detail-label">
                  Пароль
                </div>

                <div className="password-row">
                  <input
                    className="password-display"
                    readOnly
                    type={
                      passwordVisible
                        ? "text"
                        : "password"
                    }
                    value={
                      selectedEntry.password
                    }
                    spellCheck={false}
                  />

                  <button
                    type="button"
                    className="reveal-button"
                    onClick={() =>
                      setPasswordVisible(
                        (value) => !value,
                      )
                    }
                  >
                    {passwordVisible
                      ? "Скрыть"
                      : "Показать"}
                  </button>

                  <button
                    type="button"
                    className="reveal-button"
                    disabled={copyBusy}
                    onClick={() =>
                      void handleCopyPassword()
                    }
                  >
                    {copyBusy
                      ? "Копируем…"
                      : "Копировать"}
                  </button>
                </div>

                <div className="copy-disabled-note">
                  {copyMessage ??
                    "Защищённое копирование: автоочистка через 30 секунд; новое содержимое буфера LocalVault не удаляет."}
                </div>
              </div>
              <div className="detail-section">
                <div className="detail-label">
                  Сайт
                </div>
                <div className="detail-value breakable">
                  {selectedEntry.url || "—"}
                </div>
              </div>

              {selectedEntry.notes && (
                <div className="detail-section">
                  <div className="detail-label">
                    Заметки
                  </div>
                  <div className="notes-value">
                    {selectedEntry.notes}
                  </div>
                </div>
              )}

              {selectedEntry.tags.length > 0 && (
                <div className="detail-section">
                  <div className="detail-label">
                    Теги
                  </div>
                  <div className="tag-list">
                    {selectedEntry.tags.map(
                      (tag) => (
                        <span
                          className="tag"
                          key={tag}
                        >
                          {tag}
                        </span>
                      ),
                    )}
                  </div>
                </div>
              )}

              <div className="detail-meta">
                Обновлено{" "}
                {formatTimestamp(
                  selectedEntry.updatedAtMs,
                )}
              </div>
            </div>
          )}
        </section>
      </div>
      {categoryEditorMode && (
        <CategoryEditor
          key={
            categoryEditorMode === "edit" &&
            editingCategory
              ? `edit-${editingCategory.id}`
              : "create"
          }
          mode={categoryEditorMode}
          category={
            categoryEditorMode === "edit"
              ? editingCategory
              : null
          }
          busy={categoryMutationBusy}
          errorMessage={
            categoryMutationError
          }
          onCancel={() => {
            if (!categoryMutationBusy) {
              setCategoryEditorMode(null);
              setEditingCategory(null);
              setCategoryMutationError(null);
            }
          }}
          onSubmit={
            handleCategorySubmit
          }
          onDelete={
            handleDeleteCategory
          }
        />
      )}
      {entryEditorMode && (
        <EntryEditor
          key={
            entryEditorMode === "edit" &&
            selectedEntry
              ? `edit-${selectedEntry.id}`
              : "create"
          }
          mode={entryEditorMode}
          initialEntry={
            entryEditorMode === "edit"
              ? selectedEntry
              : null
          }
          categories={categories}
          busy={entryMutationBusy}
          errorMessage={
            entryMutationError
          }
          onCancel={() => {
            if (!entryMutationBusy) {
              setEntryEditorMode(null);
              setEntryMutationError(null);
            }
          }}
          onSubmit={
            handleEntrySubmit
          }
        />
      )}
    </main>
  );
}

export default App;
