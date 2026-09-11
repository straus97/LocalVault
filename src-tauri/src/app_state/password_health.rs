use std::collections::{HashMap, HashSet};

use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::vault::data::VaultData;

use super::{AppState, AppStateError};

const MIN_PASSWORD_LENGTH: usize = 12;

const SINGLE_CLASS_MIN_LENGTH: usize = 20;

const COMMON_PASSWORDS: &[&str] = &[
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "111111",
    "000000",
    "abc123",
    "admin",
    "letmein",
    "password",
    "password1",
    "qwerty",
    "qwerty123",
    "welcome",
    "iloveyou",
];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PasswordWeakReason {
    Empty,
    TooShort,
    CommonPassword,
    LowVariety,
    SingleCharacterClass,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHealthItem {
    pub entry_id: Uuid,
    pub title: String,
    pub profile_name: String,
    pub url: String,
    pub username: String,
    pub weak: bool,
    pub reused: bool,
    pub weak_reasons: Vec<PasswordWeakReason>,
}

impl Drop for PasswordHealthItem {
    fn drop(&mut self) {
        self.title.zeroize();
        self.profile_name.zeroize();
        self.url.zeroize();
        self.username.zeroize();
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHealthReport {
    pub total_entries: usize,
    pub weak_entries: usize,
    pub reused_entries: usize,
    pub affected_entries: usize,
    pub items: Vec<PasswordHealthItem>,
}

fn is_common_password(password: &str) -> bool {
    COMMON_PASSWORDS
        .iter()
        .any(|candidate| password.eq_ignore_ascii_case(candidate))
}

fn password_character_classes(password: &str) -> usize {
    let mut lowercase = false;
    let mut uppercase = false;
    let mut digits = false;
    let mut symbols = false;

    for character in password.chars() {
        if character.is_lowercase() {
            lowercase = true;
        } else if character.is_uppercase() {
            uppercase = true;
        } else if character.is_numeric() {
            digits = true;
        } else {
            symbols = true;
        }
    }

    usize::from(lowercase) + usize::from(uppercase) + usize::from(digits) + usize::from(symbols)
}

fn weak_reasons(password: &str) -> Vec<PasswordWeakReason> {
    if password.is_empty() {
        return vec![PasswordWeakReason::Empty];
    }

    let length = password.chars().count();

    let mut reasons = Vec::new();

    if length < MIN_PASSWORD_LENGTH {
        reasons.push(PasswordWeakReason::TooShort);
    }

    if is_common_password(password) {
        reasons.push(PasswordWeakReason::CommonPassword);
    }

    /*
     * Track only individual characters, never a
     * second password String.
     *
     * This is transient derived state and is
     * dropped when the analysis call finishes.
     */
    let mut unique_characters = HashSet::new();

    for character in password.chars() {
        unique_characters.insert(character);
    }

    if length >= 4 && unique_characters.len() <= 3 {
        reasons.push(PasswordWeakReason::LowVariety);
    }

    if length < SINGLE_CLASS_MIN_LENGTH && password_character_classes(password) <= 1 {
        reasons.push(PasswordWeakReason::SingleCharacterClass);
    }

    reasons
}

fn analyze_password_health(data: &VaultData) -> PasswordHealthReport {
    /*
     * Keys borrow the already decrypted password
     * Strings owned by VaultData.
     *
     * No password copy, fingerprint or persistent
     * hash is created by this feature.
     */
    let mut reuse_counts: HashMap<&str, usize> = HashMap::new();

    for entry in &data.entries {
        if entry.password.is_empty() {
            continue;
        }

        *reuse_counts.entry(entry.password.as_str()).or_default() += 1;
    }

    let mut weak_entries = 0usize;
    let mut reused_entries = 0usize;
    let mut items = Vec::new();

    for entry in &data.entries {
        let reasons = weak_reasons(entry.password.as_str());

        let weak = !reasons.is_empty();

        /*
         * Empty passwords are weakness findings,
         * but several empty fields are not treated
         * as "password reuse".
         */
        let reused = !entry.password.is_empty()
            && reuse_counts
                .get(entry.password.as_str())
                .copied()
                .unwrap_or(0)
                > 1;

        if weak {
            weak_entries += 1;
        }

        if reused {
            reused_entries += 1;
        }

        if !weak && !reused {
            continue;
        }

        items.push(PasswordHealthItem {
            entry_id: entry.id,
            title: entry.title.clone(),
            profile_name: entry.profile_name.clone(),
            url: entry.url.clone(),
            username: entry.username.clone(),
            weak,
            reused,
            weak_reasons: reasons,
        });
    }

    PasswordHealthReport {
        total_entries: data.entries.len(),
        weak_entries,
        reused_entries,
        affected_entries: items.len(),
        items,
    }
}

impl AppState {
    pub fn password_health(&self) -> Result<PasswordHealthReport, AppStateError> {
        /*
         * Analysis is available only for an active
         * unlocked session. active_session_guard
         * also preserves the existing inactivity
         * timeout semantics.
         */
        let guard = self.active_session_guard()?;

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        Ok(analyze_password_health(session.data()))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::*;
    use crate::vault::{data::VaultEntry, session::EntryInput};

    const NOW_MS: i64 = 1_700_000_000_000;

    const MASTER_PASSWORD: &str = "password-health-master-test-only";

    const REUSED_SECRET: &str = "Correct-Horse-Battery-Staple!47";

    const WEAK_SECRET: &str = "tiny";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    fn data_entry(title: &str, password: &str) -> VaultEntry {
        let mut entry = VaultEntry::new(title, NOW_MS).unwrap();

        entry.profile_name = "Personal".to_owned();

        entry.url = format!(
            "https://{}.example.test",
            title.to_ascii_lowercase().replace(' ', "-"),
        );

        entry.username = format!(
            "{}@example.test",
            title.to_ascii_lowercase().replace(' ', "."),
        );

        entry.password = password.to_owned();

        entry
    }

    fn entry_input(title: &str, password: &str) -> EntryInput {
        EntryInput {
            title: title.to_owned(),
            profile_name: "Personal".to_owned(),
            url: "https://health.example.test".to_owned(),
            username: "health-user@example.test".to_owned(),
            password: password.to_owned(),
            notes: String::new(),
            category_id: None,
            tags: Vec::new(),
            favorite: false,
        }
    }

    #[test]
    fn empty_vault_has_empty_health_report() {
        let data = VaultData::new(NOW_MS).unwrap();

        let report = analyze_password_health(&data);

        assert_eq!(report.total_entries, 0);
        assert_eq!(report.weak_entries, 0);
        assert_eq!(report.reused_entries, 0);
        assert_eq!(report.affected_entries, 0);
        assert!(report.items.is_empty());
    }

    #[test]
    fn empty_password_is_weak_but_not_reused() {
        let mut data = VaultData::new(NOW_MS).unwrap();

        data.entries.push(data_entry("Empty One", ""));

        data.entries.push(data_entry("Empty Two", ""));

        let report = analyze_password_health(&data);

        assert_eq!(report.weak_entries, 2);
        assert_eq!(report.reused_entries, 0);

        assert!(report.items.iter().all(|item| {
            item.weak && !item.reused && item.weak_reasons.contains(&PasswordWeakReason::Empty)
        },));
    }

    #[test]
    fn exact_password_reuse_is_detected() {
        let mut data = VaultData::new(NOW_MS).unwrap();

        data.entries.push(data_entry("First", REUSED_SECRET));

        data.entries.push(data_entry("Second", REUSED_SECRET));

        data.entries.push(data_entry(
            "Different Case",
            "correct-horse-battery-staple!47",
        ));

        let report = analyze_password_health(&data);

        assert_eq!(report.reused_entries, 2);

        let reused = report.items.iter().filter(|item| item.reused).count();

        assert_eq!(reused, 2);
    }

    #[test]
    fn strong_unique_password_creates_no_issue() {
        let mut data = VaultData::new(NOW_MS).unwrap();

        data.entries.push(data_entry("Strong", "R7!mQ2#vL9@xT4$z"));

        let report = analyze_password_health(&data);

        assert_eq!(report.total_entries, 1);
        assert_eq!(report.weak_entries, 0);
        assert_eq!(report.reused_entries, 0);
        assert!(report.items.is_empty());
    }

    #[test]
    fn common_short_password_reports_reasons() {
        let mut data = VaultData::new(NOW_MS).unwrap();

        data.entries.push(data_entry("Weak", "password"));

        let report = analyze_password_health(&data);

        assert_eq!(report.weak_entries, 1);

        let item = &report.items[0];

        assert!(item.weak_reasons.contains(&PasswordWeakReason::TooShort,));

        assert!(item
            .weak_reasons
            .contains(&PasswordWeakReason::CommonPassword,));

        assert!(item
            .weak_reasons
            .contains(&PasswordWeakReason::SingleCharacterClass,));
    }

    #[test]
    fn serialized_report_contains_no_raw_passwords() {
        let mut data = VaultData::new(NOW_MS).unwrap();

        data.entries.push(data_entry("Reused A", REUSED_SECRET));

        data.entries.push(data_entry("Reused B", REUSED_SECRET));

        data.entries.push(data_entry("Weak", WEAK_SECRET));

        let report = analyze_password_health(&data);

        let serialized = serde_json::to_string(&report).unwrap();

        assert!(!serialized.contains(REUSED_SECRET,));

        assert!(!serialized.contains(WEAK_SECRET,));
    }

    #[test]
    fn locked_state_rejects_health_analysis() {
        let state = AppState::default();

        assert!(matches!(
            state.password_health(),
            Err(AppStateError::VaultLocked)
        ));
    }

    #[test]
    fn health_analysis_is_read_only_and_not_persisted() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path.clone(), password()).unwrap();

        state
            .create_entry(entry_input("Weak", WEAK_SECRET))
            .unwrap();

        let before = fs::read(&path).unwrap();

        let report = state.password_health().unwrap();

        let after = fs::read(&path).unwrap();

        assert_eq!(before, after);

        assert_eq!(report.total_entries, 1);

        assert_eq!(report.weak_entries, 1);

        let serialized = serde_json::to_string(&report).unwrap();

        assert!(!serialized.contains(WEAK_SECRET,));
    }
}
