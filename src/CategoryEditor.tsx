import {
  type FormEvent,
} from "react";

import type {
  CategorySummary,
} from "./types";

interface CategoryEditorProps {
  mode: "create" | "edit";
  category: CategorySummary | null;
  busy: boolean;
  errorMessage: string | null;
  onCancel: () => void;
  onSubmit: (
    name: string,
  ) => Promise<void>;
  onDelete: () => Promise<void>;
}

export default function CategoryEditor({
  mode,
  category,
  busy,
  errorMessage,
  onCancel,
  onSubmit,
  onDelete,
}: CategoryEditorProps) {
  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (busy) {
      return;
    }

    const formData =
      new FormData(event.currentTarget);

    const value =
      formData.get("name");

    const name =
      typeof value === "string"
        ? value
        : "";

    await onSubmit(name);
  }

  return (
    <div
      className="modal-backdrop category-modal-backdrop"
      role="presentation"
    >
      <section
        className="category-editor"
        role="dialog"
        aria-modal="true"
        aria-labelledby="category-editor-title"
      >
        <header className="editor-header">
          <div>
            <span className="editor-eyebrow">
              {mode === "create"
                ? "Новая категория"
                : "Категория"}
            </span>

            <h2 id="category-editor-title">
              {mode === "create"
                ? "Создать категорию"
                : "Изменить категорию"}
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

        <form
          className="category-editor-form"
          autoComplete="off"
          onSubmit={(event) =>
            void handleSubmit(event)
          }
        >
          {errorMessage && (
            <div
              className="editor-error category-editor-error"
              role="alert"
            >
              {errorMessage}
            </div>
          )}

          <label className="editor-field">
            <span>
              Название категории
              <strong>*</strong>
            </span>

            <input
              autoFocus
              name="name"
              type="text"
              required
              maxLength={128}
              defaultValue={
                category?.name ?? ""
              }
              placeholder="Например, Работа"
              disabled={busy}
              autoComplete="off"
            />
          </label>

          <p className="category-editor-note">
            Категория хранится только внутри
            зашифрованного сейфа и используется
            для организации записей.
          </p>

          {mode === "edit" && (
            <div className="category-danger-zone">
              <div>
                <strong>
                  Удалить категорию
                </strong>

                <span>
                  Если категория используется
                  хотя бы одной записью,
                  LocalVault не позволит её
                  удалить.
                </span>
              </div>

              <button
                type="button"
                className="category-delete-button"
                disabled={busy}
                onClick={() =>
                  void onDelete()
                }
              >
                Удалить
              </button>
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
              {busy
                ? "Сохраняем…"
                : mode === "create"
                  ? "Создать категорию"
                  : "Сохранить"}
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}
