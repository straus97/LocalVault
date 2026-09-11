import {
  type FormEvent,
  useRef,
  useState,
} from "react";

import type {
  CategorySummary,
  EntryCommandInput,
  EntryDetails,
} from "./types";

import {
  generatePassword,
} from "./vaultApi";

interface EntryCreatePreset {
  title: string;
  url: string;
}

interface EntryEditorProps {
  mode: "create" | "edit";
  initialEntry: EntryDetails | null;
  createPreset: EntryCreatePreset | null;
  categories: CategorySummary[];
  busy: boolean;
  errorMessage: string | null;
  onCancel: () => void;
  onSubmit: (
    input: EntryCommandInput,
  ) => Promise<void>;
}

function fieldValue(
  formData: FormData,
  name: string,
): string {
  const value = formData.get(name);

  return typeof value === "string"
    ? value
    : "";
}

function parseTags(
  rawTags: string,
): string[] {
  const tags = rawTags
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean);

  return [...new Set(tags)];
}

export default function EntryEditor({
  mode,
  initialEntry,
  createPreset,
  categories,
  busy,
  errorMessage,
  onCancel,
  onSubmit,
}: EntryEditorProps) {
  const creatingProfile =
    mode === "create" &&
    createPreset !== null;

  const passwordInputRef =
    useRef<HTMLInputElement | null>(null);

  const [passwordVisible, setPasswordVisible] =
    useState(false);

  const [generatorBusy, setGeneratorBusy] =
    useState(false);

  const [generatorMessage, setGeneratorMessage] =
    useState<string | null>(null);

  const [generatorLength, setGeneratorLength] =
    useState(20);

  const [includeLowercase, setIncludeLowercase] =
    useState(true);

  const [includeUppercase, setIncludeUppercase] =
    useState(true);

  const [includeDigits, setIncludeDigits] =
    useState(true);

  const [includeSymbols, setIncludeSymbols] =
    useState(true);

  async function handleGeneratePassword() {
    if (busy || generatorBusy) {
      return;
    }

    if (
      !includeLowercase &&
      !includeUppercase &&
      !includeDigits &&
      !includeSymbols
    ) {
      setGeneratorMessage(
        "Выберите хотя бы один набор символов.",
      );

      return;
    }

    const length =
      Math.min(
        128,
        Math.max(
          12,
          Number.isFinite(generatorLength)
            ? Math.trunc(generatorLength)
            : 20,
        ),
      );

    setGeneratorLength(length);
    setGeneratorBusy(true);
    setGeneratorMessage(null);

    try {
      const result =
        await generatePassword({
          length,
          includeLowercase,
          includeUppercase,
          includeDigits,
          includeSymbols,
        });

      const input =
        passwordInputRef.current;

      if (!input) {
        /*
         * Best-effort reference shortening. JavaScript strings
         * themselves cannot be reliably zeroized.
         */
        result.password = "";

        setGeneratorMessage(
          "Поле пароля уже закрыто.",
        );

        return;
      }

      /*
       * Do not put the generated password in React state.
       * Assign it directly to the uncontrolled password input.
       */
      input.value =
        result.password;

      /*
       * Remove our response-object reference immediately.
       */
      result.password = "";

      setPasswordVisible(false);

      setGeneratorMessage(
        `Создан пароль длиной ${length} символов.`,
      );
    } catch {
      setGeneratorMessage(
        "Не удалось безопасно сгенерировать пароль.",
      );
    } finally {
      setGeneratorBusy(false);
    }
  }

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (busy) {
      return;
    }

    const formData =
      new FormData(
        event.currentTarget,
      );

    const rawCategoryId =
      fieldValue(
        formData,
        "categoryId",
      );

    const input: EntryCommandInput = {
      title: fieldValue(
        formData,
        "title",
      ),

      profileName: fieldValue(
        formData,
        "profileName",
      ),

      url: fieldValue(
        formData,
        "url",
      ),

      username: fieldValue(
        formData,
        "username",
      ),

      password: fieldValue(
        formData,
        "password",
      ),

      notes: fieldValue(
        formData,
        "notes",
      ),

      categoryId:
        rawCategoryId || null,

      tags: parseTags(
        fieldValue(
          formData,
          "tags",
        ),
      ),

      favorite:
        formData.has(
          "favorite",
        ),
    };

    await onSubmit(input);
  }

  return (
    <div
      className="modal-backdrop"
      role="presentation"
    >
      <section
        className="entry-editor"
        role="dialog"
        aria-modal="true"
        aria-labelledby="entry-editor-title"
      >
        <header className="editor-header">
          <div>
            <span className="editor-eyebrow">
              {mode === "create"
                ? creatingProfile
                  ? "Новый профиль"
                  : "Новая запись"
                : "Редактирование"}
            </span>

            <h2 id="entry-editor-title">
              {mode === "create"
                ? creatingProfile
                  ? "Добавить профиль"
                  : "Добавить учётную запись"
                : "Изменить учётную запись"}
            </h2>
          </div>

          <button
            type="button"
            className="editor-close"
            disabled={busy}
            aria-label="Закрыть"
            onClick={onCancel}
          >
            ×
          </button>
        </header>

        {errorMessage && (
          <div
            className="editor-error"
            role="alert"
          >
            {errorMessage}
          </div>
        )}

        <form
          className="editor-form"
          autoComplete="off"
          onSubmit={(event) =>
            void handleSubmit(event)
          }
        >
          <div className="editor-grid">
            <label className="editor-field">
              <span>
                Название
                <strong>*</strong>
              </span>

              <input
                autoFocus
                name="title"
                type="text"
                required
                maxLength={256}
                defaultValue={
                  initialEntry?.title ??
                  createPreset?.title ??
                  ""
                }
                placeholder="Например, GitHub"
                disabled={busy}
                autoComplete="off"
              />
            </label>

            <label className="editor-field">
              <span>Название профиля</span>

              <input
                name="profileName"
                type="text"
                maxLength={128}
                defaultValue={
                  initialEntry?.profileName ??
                  ""
                }
                placeholder="Например, Личный или Работа"
                disabled={busy}
                autoComplete="off"
              />
            </label>

            <label className="editor-field">
              <span>Логин</span>

              <input
                name="username"
                type="text"
                defaultValue={
                  initialEntry?.username ?? ""
                }
                placeholder="user@example.com"
                disabled={busy}
                autoComplete="off"
                spellCheck={false}
              />
            </label>

            <label className="editor-field">
              <span>Сайт</span>

              <input
                name="url"
                type="text"
                defaultValue={
                  initialEntry?.url ??
                  createPreset?.url ??
                  ""
                }
                placeholder="https://example.com"
                disabled={busy}
                autoComplete="off"
                spellCheck={false}
              />
            </label>

            <label className="editor-field span-two">
              <span>Пароль</span>

              <div className="editor-password">
                <input
                  ref={passwordInputRef}
                  name="password"
                  type={
                    passwordVisible
                      ? "text"
                      : "password"
                  }
                  defaultValue={
                    initialEntry?.password ?? ""
                  }
                  disabled={busy}
                  autoComplete="new-password"
                  spellCheck={false}
                />

                <button
                  type="button"
                  disabled={
                    busy ||
                    generatorBusy
                  }
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
              </div>

              <div className="password-generator">
                <div className="password-generator-head">
                  <strong>
                    Генератор пароля
                  </strong>

                  <label className="generator-length">
                    <span>Длина</span>

                    <input
                      type="number"
                      min={12}
                      max={128}
                      step={1}
                      value={generatorLength}
                      disabled={
                        busy ||
                        generatorBusy
                      }
                      onChange={(event) =>
                        setGeneratorLength(
                          Number(
                            event.currentTarget
                              .value,
                          ),
                        )
                      }
                    />
                  </label>

                  <button
                    type="button"
                    className="editor-secondary generator-button"
                    disabled={
                      busy ||
                      generatorBusy
                    }
                    onClick={() =>
                      void handleGeneratePassword()
                    }
                  >
                    {generatorBusy
                      ? "Генерируем…"
                      : "Сгенерировать"}
                  </button>
                </div>

                <div className="password-generator-options">
                  <label>
                    <input
                      type="checkbox"
                      checked={
                        includeLowercase
                      }
                      disabled={
                        busy ||
                        generatorBusy
                      }
                      onChange={(event) =>
                        setIncludeLowercase(
                          event.currentTarget
                            .checked,
                        )
                      }
                    />
                    <span>a-z</span>
                  </label>

                  <label>
                    <input
                      type="checkbox"
                      checked={
                        includeUppercase
                      }
                      disabled={
                        busy ||
                        generatorBusy
                      }
                      onChange={(event) =>
                        setIncludeUppercase(
                          event.currentTarget
                            .checked,
                        )
                      }
                    />
                    <span>A-Z</span>
                  </label>

                  <label>
                    <input
                      type="checkbox"
                      checked={
                        includeDigits
                      }
                      disabled={
                        busy ||
                        generatorBusy
                      }
                      onChange={(event) =>
                        setIncludeDigits(
                          event.currentTarget
                            .checked,
                        )
                      }
                    />
                    <span>0-9</span>
                  </label>

                  <label>
                    <input
                      type="checkbox"
                      checked={
                        includeSymbols
                      }
                      disabled={
                        busy ||
                        generatorBusy
                      }
                      onChange={(event) =>
                        setIncludeSymbols(
                          event.currentTarget
                            .checked,
                        )
                      }
                    />
                    <span>!@#…</span>
                  </label>
                </div>

                <div
                  className="password-generator-message"
                  aria-live="polite"
                >
                  {generatorMessage ??
                    "Криптографическая случайность ОС. Длина 12–128 символов."}
                </div>
              </div>
            </label>

            <label className="editor-field">
              <span>Категория</span>

              <select
                name="categoryId"
                defaultValue={
                  initialEntry?.categoryId ??
                  ""
                }
                disabled={busy}
              >
                <option value="">
                  Без категории
                </option>

                {categories.map(
                  (category) => (
                    <option
                      key={category.id}
                      value={category.id}
                    >
                      {category.name}
                    </option>
                  ),
                )}
              </select>
            </label>

            <label className="editor-field">
              <span>Теги</span>

              <input
                name="tags"
                type="text"
                defaultValue={
                  initialEntry?.tags.join(
                    ", ",
                  ) ?? ""
                }
                placeholder="работа, почта"
                disabled={busy}
                autoComplete="off"
              />
            </label>

            <label className="editor-field span-two">
              <span>Заметки</span>

              <textarea
                name="notes"
                rows={5}
                defaultValue={
                  initialEntry?.notes ?? ""
                }
                placeholder="Дополнительная информация"
                disabled={busy}
              />
            </label>
          </div>

          <label className="favorite-control">
            <input
              name="favorite"
              type="checkbox"
              defaultChecked={
                initialEntry?.favorite ??
                false
              }
              disabled={busy}
            />

            <span>
              Добавить в избранное
            </span>
          </label>

          <div className="editor-security-note">
            Генерация выполняется в Rust через
            системный криптографический источник.
            Несохранённый пароль исчезает при
            закрытии редактора или блокировке сейфа.
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
              disabled={busy}
            >
              {busy
                ? "Сохраняем…"
                : mode === "create"
                  ? creatingProfile
                    ? "Добавить профиль"
                    : "Создать запись"
                  : "Сохранить изменения"}
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}
