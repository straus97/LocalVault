use std::time::Instant;

use serde::Serialize;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    totp::generate_totp,
    vault::session::{SessionError, UnlockedVaultSession},
};

use super::{unix_time_ms, AppState, AppStateError};

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    pub expires_at_ms: i64,
    pub period_seconds: u32,
    pub digits: u8,
}

impl Drop for TotpCode {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

fn generate_for_entry(
    session: &UnlockedVaultSession,
    id: Uuid,
    now_ms: i64,
) -> Result<TotpCode, AppStateError> {
    let entry = session
        .data()
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .ok_or(AppStateError::Session(SessionError::EntryNotFound))?;

    let config = entry
        .totp
        .as_ref()
        .ok_or(AppStateError::TotpNotConfigured)?;

    let generated =
        generate_totp(config, now_ms).map_err(|_| AppStateError::TotpGenerationFailed)?;

    let (code, expires_at_ms, period_seconds, digits) = generated.into_parts();

    Ok(TotpCode {
        code,
        expires_at_ms,
        period_seconds,
        digits,
    })
}

impl AppState {
    pub fn entry_totp_code(&self, id: Uuid) -> Result<TotpCode, AppStateError> {
        let now_ms = unix_time_ms()?;

        /*
         * Display refresh is passive.
         *
         * TOTP code rotation must not refresh last_activity,
         * otherwise a visible TOTP could keep the vault
         * unlocked forever.
         */
        let mut guard = self.inner_guard()?;

        if self.expire_if_needed(&mut guard, Instant::now()) {
            return Err(AppStateError::SessionExpired);
        }

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        generate_for_entry(session, id, now_ms)
    }

    pub fn entry_totp_for_clipboard(&self, id: Uuid) -> Result<Zeroizing<String>, AppStateError> {
        let now_ms = unix_time_ms()?;

        /*
         * Copy is an explicit user action, so unlike passive
         * display refresh it counts as activity.
         */
        let guard = self.active_session_guard()?;

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        let mut generated = generate_for_entry(session, id, now_ms)?;

        Ok(Zeroizing::new(std::mem::take(&mut generated.code)))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use crate::{totp::parse_totp_input, vault::session::EntryInput};

    use super::*;

    const MASTER_PASSWORD: &str = "totp-state-master-password-test-only";

    const TOTP_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    const TOTP_SECRET_BASE64: &str = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    fn input() -> EntryInput {
        EntryInput {
            title: "TOTP test account".to_owned(),

            profile_name: "Personal".to_owned(),

            url: "https://totp.example.test".to_owned(),

            username: "totp-user@example.test".to_owned(),

            password: "TOTP_TEST_PASSWORD".to_owned(),

            notes: "TOTP_TEST_NOTE".to_owned(),

            category_id: None,

            tags: vec!["totp-test".to_owned()],

            favorite: false,
        }
    }

    fn create_totp_entry(state: &AppState, path: std::path::PathBuf) -> Uuid {
        state.create_vault(path, password()).unwrap();

        state
            .create_entry_with_totp(input(), parse_totp_input(TOTP_BASE32).unwrap())
            .unwrap()
            .id
    }

    #[test]
    fn locked_state_rejects_totp_generation() {
        let state = AppState::default();

        assert!(matches!(
            state.entry_totp_code(Uuid::new_v4(),),
            Err(AppStateError::VaultLocked)
        ));
    }

    #[test]
    fn missing_totp_is_reported() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("missing-totp.lvault");

        let state = AppState::default();

        state.create_vault(path, password()).unwrap();

        let created = state.create_entry(input()).unwrap();

        assert!(matches!(
            state.entry_totp_code(created.id,),
            Err(AppStateError::TotpNotConfigured)
        ));
    }

    #[test]
    fn passive_totp_refresh_does_not_extend_activity() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("totp-passive.lvault");

        let state = AppState::default();

        let id = create_totp_entry(&state, path);

        let before = {
            let guard = state.inner.lock().unwrap();

            guard.last_activity
        };

        state.entry_totp_code(id).unwrap();

        let after = {
            let guard = state.inner.lock().unwrap();

            guard.last_activity
        };

        assert_eq!(after, before,);
    }

    #[test]
    fn clipboard_totp_lookup_counts_as_activity() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("totp-active-copy.lvault");

        let state = AppState::default();

        let id = create_totp_entry(&state, path);

        state.age_session_for_test(std::time::Duration::from_secs(30));

        let before = {
            let guard = state.inner.lock().unwrap();

            guard.last_activity.unwrap()
        };

        state.entry_totp_for_clipboard(id).unwrap();

        let after = {
            let guard = state.inner.lock().unwrap();

            guard.last_activity.unwrap()
        };

        assert!(after > before);
    }

    #[test]
    fn totp_persists_without_exposing_secret_in_dtos() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("totp-persist.lvault");

        let state = AppState::default();

        let id = create_totp_entry(&state, path.clone());

        let details = state.get_entry(id).unwrap();

        assert!(details.totp_enabled);

        let serialized = serde_json::to_string(&details).unwrap();

        assert!(!serialized.contains(TOTP_BASE32,));

        assert!(!serialized.contains(TOTP_SECRET_BASE64,));

        assert!(!serialized.contains("secretBase64",));

        let generated = state.entry_totp_code(id).unwrap();

        assert_eq!(generated.code.len(), 6,);

        assert_eq!(generated.period_seconds, 30,);

        assert_eq!(generated.digits, 6,);

        let raw = fs::read_to_string(&path).unwrap();

        assert!(!raw.contains(TOTP_BASE32,));

        assert!(!raw.contains(TOTP_SECRET_BASE64,));

        state.lock_vault().unwrap();

        state.unlock_vault(path, password()).unwrap();

        assert!(state.get_entry(id).unwrap().totp_enabled);
    }

    #[test]
    fn clipboard_lookup_returns_only_current_code() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("totp-clipboard.lvault");

        let state = AppState::default();

        let id = create_totp_entry(&state, path);

        let code = state.entry_totp_for_clipboard(id).unwrap();

        assert_eq!(code.len(), 6,);

        assert_ne!(code.as_str(), TOTP_BASE32,);

        assert_ne!(code.as_str(), TOTP_SECRET_BASE64,);
    }
}
