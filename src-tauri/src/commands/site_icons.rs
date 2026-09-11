use tauri::State;
use zeroize::Zeroizing;

use crate::{
    app_state::{AppState, SiteIconSummary},
    site_icon_fetcher::{fetch_site_icon as fetch_remote_site_icon, SiteIconFetchError},
};

use super::CommandError;

fn map_fetch_error(error: SiteIconFetchError) -> CommandError {
    match error {
        SiteIconFetchError::InvalidHostname => {
            CommandError::new("invalidSiteHostname", "The site hostname is invalid.")
        }

        SiteIconFetchError::UnsafeNetworkTarget
        | SiteIconFetchError::InsecureScheme
        | SiteIconFetchError::UnsupportedPort => CommandError::new(
            "unsafeSiteIconTarget",
            "The site icon target is not allowed.",
        ),

        SiteIconFetchError::DnsResolutionFailed => CommandError::new(
            "siteIconDnsFailed",
            "The site hostname could not be resolved.",
        ),

        SiteIconFetchError::NoIconFound => {
            CommandError::new("siteIconNotFound", "No usable site icon was found.")
        }

        SiteIconFetchError::InvalidRedirect
        | SiteIconFetchError::RedirectLimit
        | SiteIconFetchError::RequestFailed
        | SiteIconFetchError::ResponseTooLarge
        | SiteIconFetchError::UnexpectedContentType
        | SiteIconFetchError::InvalidImage
        | SiteIconFetchError::UnsafeImageDimensions
        | SiteIconFetchError::NormalizedImageTooLarge => CommandError::new(
            "siteIconFetchFailed",
            "The site icon could not be downloaded safely.",
        ),
    }
}

#[tauri::command]
pub fn list_site_icons(state: State<'_, AppState>) -> Result<Vec<SiteIconSummary>, CommandError> {
    state.list_site_icons().map_err(CommandError::from)
}

#[tauri::command]
pub async fn fetch_site_icon(
    hostname: String,
    state: State<'_, AppState>,
) -> Result<SiteIconSummary, CommandError> {
    let hostname = Zeroizing::new(hostname);

    /*
     * Verify the hostname belongs to the current
     * unlocked vault before performing any network
     * request.
     */
    state
        .ensure_site_hostname_referenced(hostname.as_str())
        .map_err(CommandError::from)?;

    let fetched = fetch_remote_site_icon(hostname.as_str())
        .await
        .map_err(map_fetch_error)?;

    /*
     * store_site_icon checks the relationship
     * again after the async network operation and
     * persists the normalized PNG transactionally.
     */
    state
        .store_site_icon(fetched.hostname, fetched.png_bytes)
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn delete_site_icon(
    hostname: String,
    state: State<'_, AppState>,
) -> Result<bool, CommandError> {
    let hostname = Zeroizing::new(hostname);

    state
        .delete_site_icon(hostname.as_str())
        .map_err(CommandError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_hostname_has_stable_error() {
        let error = map_fetch_error(SiteIconFetchError::InvalidHostname);

        assert_eq!(error.code, "invalidSiteHostname");
    }

    #[test]
    fn unsafe_target_has_stable_error() {
        let error = map_fetch_error(SiteIconFetchError::UnsafeNetworkTarget);

        assert_eq!(error.code, "unsafeSiteIconTarget");
    }

    #[test]
    fn missing_icon_has_stable_error() {
        let error = map_fetch_error(SiteIconFetchError::NoIconFound);

        assert_eq!(error.code, "siteIconNotFound");
    }

    #[test]
    fn transport_details_are_sanitized() {
        let error = map_fetch_error(SiteIconFetchError::RequestFailed);

        assert_eq!(error.code, "siteIconFetchFailed");

        assert_eq!(
            error.message,
            "The site icon could not be downloaded safely."
        );
    }
}
