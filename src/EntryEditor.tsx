import {
  type FormEvent,
  useState,
} from "react";

import type {
  CategorySummary,
  EntryCommandInput,
  EntryDetails,
} from "./types";

interface EntryEditorProps {
  mode: "create" | "edit";
  initialEntry: EntryDetails | null;
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
  categories,
  busy,
  errorMessage,
  onCancel,
  onSubmit,
}: EntryEditorProps) {
  const [passwordVisible, setPasswordVisible] =
    useState(false);

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (busy) {
      return;
    }

    const formData =
      new FormData(event.currentTarget);

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
        formData.has("favorite"),
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
                ? "Новая запись"
                : "Редактирование"}
            </span>

            <h2 id="entry-editor-title">
              {mode === "create"
                ? "Добавить учётную запись"
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
            <label className="editor-field span-two">
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
                  initialEntry?.title ?? ""
                }
                placeholder="Например, GitHub"
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
                  initialEntry?.url ?? ""
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
                  disabled={busy}
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
            Пока используйте только тестовые
            данные. Безопасное копирование
            пароля и auto-lock будут добавлены
            отдельным security-этапом.
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
                  ? "Создать запись"
                  : "Сохранить изменения"}
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}
