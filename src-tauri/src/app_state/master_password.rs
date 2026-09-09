use zeroize::Zeroizing;

use super::{AppState, AppStateError};

impl AppState {
    pub fn change_master_password(
        &self,
        current_master_password: Zeroizing<String>,
        new_master_password: Zeroizing<String>,
    ) -> Result<(), AppStateError> {
        /*
         * active_session_guard performs expiry checking and
         * counts a successful password-change attempt as
         * foreground vault activity.
         */
        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        session.change_master_password(current_master_password, new_master_password)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::*;

    const OLD_PASSWORD: &str = "state-old-master-password-test-only";

    const NEW_PASSWORD: &str = "state-new-master-password-test-only";

    fn password(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    #[test]
    fn password_change_requires_unlocked_vault() {
        let state = AppState::default();

        let result = state.change_master_password(password(OLD_PASSWORD), password(NEW_PASSWORD));

        assert!(matches!(result, Err(AppStateError::VaultLocked)));
    }

    #[test]
    fn successful_password_change_keeps_session_unlocked() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state
            .create_vault(path.clone(), password(OLD_PASSWORD))
            .unwrap();

        state
            .change_master_password(password(OLD_PASSWORD), password(NEW_PASSWORD))
            .unwrap();

        assert!(state.status().unwrap().unlocked);

        state.lock_vault().unwrap();

        assert!(state
            .unlock_vault(path.clone(), password(OLD_PASSWORD,),)
            .is_err());

        assert!(!state.status().unwrap().unlocked);

        state.unlock_vault(path, password(NEW_PASSWORD)).unwrap();

        assert!(state.status().unwrap().unlocked);
    }
}
