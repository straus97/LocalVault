use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::Serialize;
use url::Url;
use zeroize::Zeroize;

use crate::vault::session::SessionError;
use localvault_core::vault::data::{SiteIcon, VaultData, VaultDataError};

use super::{unix_time_ms, AppState, AppStateError};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SiteIconSummary {
    pub hostname: String,
    pub png_base64: String,
    pub updated_at_ms: i64,
}

impl SiteIconSummary {
    fn from_icon(icon: &SiteIcon) -> Self {
        Self {
            hostname: icon.hostname.clone(),
            png_base64: icon.png_base64.clone(),
            updated_at_ms: icon.updated_at_ms,
        }
    }
}

impl Drop for SiteIconSummary {
    fn drop(&mut self) {
        self.hostname.zeroize();
        self.png_base64.zeroize();
    }
}

fn site_hostname_key(input: &str) -> Option<String> {
    let mut hostname = input.trim().trim_end_matches('.').to_ascii_lowercase();

    if let Some(without_www) = hostname.strip_prefix("www.") {
        hostname = without_www.to_owned();
    }

    if hostname.is_empty() || hostname.len() > 253 {
        return None;
    }

    if !hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }

    Some(hostname)
}

fn entry_hostname(value: &str) -> Option<String> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return None;
    }

    let parsed = Url::parse(trimmed)
        .or_else(|_| Url::parse(&format!("https://{trimmed}")))
        .ok()?;

    let hostname = parsed.host_str()?;

    site_hostname_key(hostname)
}

fn hostname_is_referenced(data: &VaultData, hostname: &str) -> bool {
    data.entries
        .iter()
        .any(|entry| entry_hostname(&entry.url).is_some_and(|candidate| candidate == hostname))
}

fn validate_icon_candidate(candidate: &VaultData) -> Result<(), AppStateError> {
    candidate.validate().map_err(|error| match error {
        VaultDataError::TooManySiteIcons | VaultDataError::TotalSiteIconDataTooLarge => {
            AppStateError::SiteIconCacheFull
        }

        other => AppStateError::Session(SessionError::Data(other)),
    })
}

impl AppState {
    pub fn list_site_icons(&self) -> Result<Vec<SiteIconSummary>, AppStateError> {
        let guard = self.active_session_guard()?;

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        Ok(session
            .data()
            .site_icons
            .iter()
            .map(SiteIconSummary::from_icon)
            .collect())
    }

    /*
     * This check happens before network access.
     *
     * A compromised frontend therefore cannot use
     * the favicon command as a generic public-web
     * request primitive. The requested hostname
     * must belong to at least one credential that
     * already exists in the unlocked vault.
     */
    pub fn ensure_site_hostname_referenced(&self, hostname: &str) -> Result<(), AppStateError> {
        let hostname =
            site_hostname_key(hostname).ok_or(AppStateError::SiteHostnameNotReferenced)?;

        let guard = self.active_session_guard()?;

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        if !hostname_is_referenced(session.data(), &hostname) {
            return Err(AppStateError::SiteHostnameNotReferenced);
        }

        Ok(())
    }

    pub fn store_site_icon(
        &self,
        hostname: String,
        png_bytes: Vec<u8>,
    ) -> Result<SiteIconSummary, AppStateError> {
        let hostname =
            site_hostname_key(&hostname).ok_or(AppStateError::SiteHostnameNotReferenced)?;

        let now_ms = unix_time_ms()?;

        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        /*
         * Re-check after the network request.
         *
         * The entry might have been edited/deleted
         * while the asynchronous fetch was running.
         */
        if !hostname_is_referenced(session.data(), &hostname) {
            return Err(AppStateError::SiteHostnameNotReferenced);
        }

        let mut candidate = session.data().clone();

        let icon = SiteIcon {
            hostname: hostname.clone(),
            png_base64: BASE64_STANDARD.encode(png_bytes),
            updated_at_ms: now_ms,
        };

        if let Some(index) = candidate
            .site_icons
            .iter()
            .position(|existing| existing.hostname == hostname)
        {
            candidate.site_icons[index] = icon;
        } else {
            candidate.site_icons.push(icon);
        }

        candidate.updated_at_ms = candidate.updated_at_ms.max(now_ms);

        validate_icon_candidate(&candidate)?;

        let summary = candidate
            .site_icons
            .iter()
            .find(|icon| icon.hostname == hostname)
            .map(SiteIconSummary::from_icon)
            .ok_or(AppStateError::StateUnavailable)?;

        /*
         * commit_candidate performs the same
         * authenticated transactional save used
         * by normal vault mutations.
         */
        session.commit_candidate(candidate)?;

        Ok(summary)
    }

    pub fn delete_site_icon(&self, hostname: &str) -> Result<bool, AppStateError> {
        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        let Some(hostname) = site_hostname_key(hostname) else {
            return Ok(false);
        };

        let mut candidate = session.data().clone();

        let Some(index) = candidate
            .site_icons
            .iter()
            .position(|icon| icon.hostname == hostname)
        else {
            return Ok(false);
        };

        candidate.site_icons.remove(index);

        let now_ms = unix_time_ms()?;

        candidate.updated_at_ms = candidate.updated_at_ms.max(now_ms);

        validate_icon_candidate(&candidate)?;

        session.commit_candidate(candidate)?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::*;
    use crate::vault::session::EntryInput;

    const MASTER_PASSWORD: &str = "site-icon-state-password-test-only";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    fn entry_input(url: &str) -> EntryInput {
        EntryInput {
            title: "Site Icon Entry".to_owned(),
            profile_name: "Personal".to_owned(),
            url: url.to_owned(),
            username: "site-icon-user".to_owned(),
            password: "SITE_ICON_SECRET".to_owned(),
            notes: String::new(),
            category_id: None,
            tags: Vec::new(),
            favorite: false,
        }
    }

    fn sample_png() -> Vec<u8> {
        /*
         * The hardened fetcher performs the real
         * image decode/normalization boundary.
         * VaultData intentionally validates the
         * cached PNG signature and size.
         */
        b"\x89PNG\r\n\x1a\nSITEICON".to_vec()
    }

    #[test]
    fn locked_state_rejects_site_icon_listing() {
        let state = AppState::default();

        assert!(matches!(
            state.list_site_icons(),
            Err(AppStateError::VaultLocked)
        ));
    }

    #[test]
    fn only_hostname_from_existing_entry_is_allowed() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path, password()).unwrap();

        state
            .create_entry(entry_input("https://www.github.com/login"))
            .unwrap();

        assert!(state.ensure_site_hostname_referenced("github.com",).is_ok());

        assert!(matches!(
            state.ensure_site_hostname_referenced("example.com",),
            Err(AppStateError::SiteHostnameNotReferenced)
        ));
    }

    #[test]
    fn stored_icon_is_encrypted_and_persists() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path.clone(), password()).unwrap();

        state
            .create_entry(entry_input("https://github.com/login"))
            .unwrap();

        let stored = state
            .store_site_icon("github.com".to_owned(), sample_png())
            .unwrap();

        assert_eq!(stored.hostname, "github.com");

        assert_eq!(state.list_site_icons().unwrap().len(), 1);

        let raw = fs::read(&path).unwrap();

        let raw_text = String::from_utf8_lossy(&raw);

        assert!(!raw_text.contains("github.com"));

        assert!(!raw_text.contains(&stored.png_base64));

        state.lock_vault().unwrap();

        state.unlock_vault(path, password()).unwrap();

        let loaded = state.list_site_icons().unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].hostname, "github.com");
    }

    #[test]
    fn storing_same_hostname_replaces_cached_icon() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path, password()).unwrap();

        state
            .create_entry(entry_input("https://github.com"))
            .unwrap();

        state
            .store_site_icon("github.com".to_owned(), sample_png())
            .unwrap();

        let mut replacement = sample_png();

        replacement.extend_from_slice(b"-replacement");

        state
            .store_site_icon("github.com".to_owned(), replacement)
            .unwrap();

        let icons = state.list_site_icons().unwrap();

        assert_eq!(icons.len(), 1);
        assert_eq!(icons[0].hostname, "github.com");
    }

    #[test]
    fn deleted_icon_stays_deleted_after_reopen() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path.clone(), password()).unwrap();

        state.create_entry(entry_input("github.com")).unwrap();

        state
            .store_site_icon("github.com".to_owned(), sample_png())
            .unwrap();

        assert!(state.delete_site_icon("github.com",).unwrap());

        assert!(state.list_site_icons().unwrap().is_empty());

        state.lock_vault().unwrap();

        state.unlock_vault(path, password()).unwrap();

        assert!(state.list_site_icons().unwrap().is_empty());
    }
}
