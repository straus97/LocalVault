import type {
  PasswordHealthItem,
  PasswordHealthReport,
  PasswordWeakReason,
} from "./types";

import "./PasswordHealthPanel.css";

const reasonLabels: Record<
  PasswordWeakReason,
  string
> = {
  empty: "Пароль не задан",
  tooShort: "Меньше 12 символов",
  commonPassword:
    "Очень распространённый пароль",
  lowVariety:
    "Слишком мало разных символов",
  singleCharacterClass:
    "Используется только один тип символов",
};

interface PasswordHealthPanelProps {
  report: PasswordHealthReport | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  onOpenEntry: (entryId: string) => void;
}

function issueMeta(
  item: PasswordHealthItem,
): string {
  return [
    item.profileName,
    item.username,
    item.url,
  ]
    .filter(Boolean)
    .join(" • ");
}

function IssueCard({
  item,
  kind,
  onOpenEntry,
}: {
  item: PasswordHealthItem;
  kind: "weak" | "reused";
  onOpenEntry: (entryId: string) => void;
}) {
  return (
    <article className="health-issue-card">
      <div className="health-issue-main">
        <div className="health-issue-title-row">
          <strong>{item.title}</strong>

          <span
            className={
              kind === "reused"
                ? "health-badge reused"
                : "health-badge weak"
            }
          >
            {kind === "reused"
              ? "Повторяется"
              : "Слабый"}
          </span>
        </div>

        <div className="health-issue-meta">
          {issueMeta(item) ||
            "Без дополнительной информации"}
        </div>

        {kind === "weak" &&
          item.weakReasons.length > 0 && (
            <div className="health-reasons">
              {item.weakReasons.map(
                (reason) => (
                  <span
                    key={reason}
                    className="health-reason"
                  >
                    {reasonLabels[reason]}
                  </span>
                ),
              )}
            </div>
          )}
      </div>

      <button
        type="button"
        className="health-open-entry"
        onClick={() =>
          onOpenEntry(item.entryId)
        }
      >
        Открыть запись
      </button>
    </article>
  );
}

export default function PasswordHealthPanel({
  report,
  loading,
  error,
  onRefresh,
  onOpenEntry,
}: PasswordHealthPanelProps) {
  const weakItems =
    report?.items.filter(
      (item) => item.weak,
    ) ?? [];

  const reusedItems =
    report?.items.filter(
      (item) => item.reused,
    ) ?? [];

  return (
    <section className="password-health-panel">
      <div className="health-header">
        <div>
          <span className="health-eyebrow">
            Локальная проверка
          </span>

          <h2>Безопасность паролей</h2>

          <p>
            Анализ выполняется только на этом
            компьютере внутри открытого сейфа.
            Пароли и их хэши не отправляются в
            интерфейс и не сохраняются отдельно.
          </p>
        </div>

        <button
          type="button"
          className="health-refresh"
          disabled={loading}
          onClick={onRefresh}
        >
          {loading
            ? "Проверяем…"
            : "Проверить снова"}
        </button>
      </div>

      {error && (
        <div className="health-error">
          {error}
        </div>
      )}

      {loading && !report ? (
        <div className="health-loading">
          <div className="detail-spinner" />

          <strong>
            Проверяем сохранённые пароли…
          </strong>

          <span>
            Анализ выполняется локально.
          </span>
        </div>
      ) : report ? (
        <>
          <div className="health-summary">
            <div className="health-summary-card attention">
              <span>Требуют внимания</span>
              <strong>
                {report.affectedEntries}
              </strong>
            </div>

            <div className="health-summary-card">
              <span>
                Потенциально слабые
              </span>
              <strong>
                {report.weakEntries}
              </strong>
            </div>

            <div className="health-summary-card">
              <span>
                Повторяющиеся
              </span>
              <strong>
                {report.reusedEntries}
              </strong>
            </div>

            <div className="health-summary-card">
              <span>Всего записей</span>
              <strong>
                {report.totalEntries}
              </strong>
            </div>
          </div>

          <div className="health-explanation">
            Это не «оценка безопасности» и не
            проверка утечек. LocalVault показывает
            только локально обнаруженные признаки,
            на которые стоит обратить внимание.
          </div>

          {report.affectedEntries === 0 ? (
            <div className="health-clean">
              <div className="health-clean-icon">
                ✓
              </div>

              <strong>
                Явных проблем не найдено
              </strong>

              <p>
                По локальным правилам проверки
                сохранённые пароли не выглядят
                слабыми и не повторяются.
              </p>
            </div>
          ) : (
            <div className="health-sections">
              <section className="health-section">
                <div className="health-section-title">
                  <div>
                    <span className="health-section-icon weak">
                      !
                    </span>

                    <div>
                      <h3>
                        Потенциально слабые
                      </h3>

                      <p>
                        Короткие, распространённые
                        или слишком однообразные
                        пароли.
                      </p>
                    </div>
                  </div>

                  <strong>
                    {weakItems.length}
                  </strong>
                </div>

                {weakItems.length === 0 ? (
                  <div className="health-section-empty">
                    Таких записей нет.
                  </div>
                ) : (
                  <div className="health-issue-list">
                    {weakItems.map((item) => (
                      <IssueCard
                        key={`weak:${item.entryId}`}
                        item={item}
                        kind="weak"
                        onOpenEntry={onOpenEntry}
                      />
                    ))}
                  </div>
                )}
              </section>

              <section className="health-section">
                <div className="health-section-title">
                  <div>
                    <span className="health-section-icon reused">
                      ↻
                    </span>

                    <div>
                      <h3>
                        Повторяющиеся пароли
                      </h3>

                      <p>
                        Один и тот же пароль
                        используется более чем в
                        одной записи.
                      </p>
                    </div>
                  </div>

                  <strong>
                    {reusedItems.length}
                  </strong>
                </div>

                {reusedItems.length === 0 ? (
                  <div className="health-section-empty">
                    Таких записей нет.
                  </div>
                ) : (
                  <div className="health-issue-list">
                    {reusedItems.map((item) => (
                      <IssueCard
                        key={`reused:${item.entryId}`}
                        item={item}
                        kind="reused"
                        onOpenEntry={onOpenEntry}
                      />
                    ))}
                  </div>
                )}
              </section>
            </div>
          )}
        </>
      ) : (
        <div className="health-loading">
          <strong>
            Проверка ещё не выполнена
          </strong>

          <span>
            Нажмите «Проверить снова».
          </span>
        </div>
      )}
    </section>
  );
}
