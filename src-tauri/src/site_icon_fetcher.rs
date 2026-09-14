use std::{
    collections::HashSet,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use image::{ImageFormat, ImageReader};
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE, LOCATION},
    redirect::Policy,
    Client, Response,
};
use scraper::{Html, Selector};
use thiserror::Error;
use tokio::net::lookup_host;
use url::Url;

use localvault_core::vault::data::MAX_SITE_ICON_BYTES;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const MAX_REDIRECTS: usize = 5;

const MAX_HTML_BYTES: usize = 512 * 1024;

const MAX_ICON_DOWNLOAD_BYTES: usize = 512 * 1024;

const MAX_ICON_CANDIDATES: usize = 12;

const MAX_IMAGE_DIMENSION: u32 = 4096;

const MAX_IMAGE_PIXELS: u64 = 16 * 1024 * 1024;

const TARGET_ICON_SIZE: u32 = 64;

const USER_AGENT: &str = "LocalVault/1.1 site-icon-fetcher";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedSiteIcon {
    pub hostname: String,
    pub png_bytes: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SiteIconFetchError {
    #[error("site hostname is invalid")]
    InvalidHostname,

    #[error("site hostname points to a non-public network target")]
    UnsafeNetworkTarget,

    #[error("site hostname could not be resolved")]
    DnsResolutionFailed,

    #[error("site URL must use HTTPS")]
    InsecureScheme,

    #[error("site URL uses an unsupported network port")]
    UnsupportedPort,

    #[error("site redirect is invalid")]
    InvalidRedirect,

    #[error("site returned too many redirects")]
    RedirectLimit,

    #[error("site request failed")]
    RequestFailed,

    #[error("site response is too large")]
    ResponseTooLarge,

    #[error("site response has an unexpected content type")]
    UnexpectedContentType,

    #[error("site icon image is invalid")]
    InvalidImage,

    #[error("site icon image dimensions are unsafe")]
    UnsafeImageDimensions,

    #[error("normalized site icon is too large")]
    NormalizedImageTooLarge,

    #[error("site icon was not found")]
    NoIconFound,
}

#[derive(Debug, Clone, Copy)]
enum ResourceKind {
    Html,
    Image,
}

impl ResourceKind {
    fn accept_header(self) -> &'static str {
        match self {
            Self::Html =>
                "text/html,application/xhtml+xml;q=0.9",

            Self::Image =>
                "image/png,image/x-icon,image/vnd.microsoft.icon,image/webp,image/jpeg,image/gif;q=0.9",
        }
    }

    fn accepts_content_type(self, content_type: &str) -> bool {
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        match self {
            Self::Html => media_type == "text/html" || media_type == "application/xhtml+xml",

            Self::Image => media_type.starts_with("image/"),
        }
    }
}

impl SiteIconFetchError {
    fn is_security_boundary_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidHostname
                | Self::UnsafeNetworkTarget
                | Self::InsecureScheme
                | Self::UnsupportedPort
        )
    }
}

pub async fn fetch_site_icon(hostname: &str) -> Result<FetchedSiteIcon, SiteIconFetchError> {
    let hostname = normalize_hostname(hostname)?;

    let root = Url::parse(&format!("https://{hostname}/"))
        .map_err(|_| SiteIconFetchError::InvalidHostname)?;

    let mut candidates = Vec::new();

    match fetch_resource(root.clone(), ResourceKind::Html, MAX_HTML_BYTES).await {
        Ok((page_url, html_bytes)) => {
            let html = String::from_utf8_lossy(&html_bytes);

            candidates.extend(discover_icon_urls(&page_url, &html));
        }

        Err(error) if error.is_security_boundary_error() => {
            return Err(error);
        }

        Err(_) => {}
    }

    if let Ok(favicon) = root.join("/favicon.ico") {
        candidates.push(favicon);
    }

    if let Ok(favicon) = root.join("/favicon.png") {
        candidates.push(favicon);
    }

    let mut seen = HashSet::with_capacity(candidates.len());

    for candidate in candidates.into_iter().take(MAX_ICON_CANDIDATES) {
        let key = candidate.as_str().to_owned();

        if !seen.insert(key) {
            continue;
        }

        match fetch_resource(candidate, ResourceKind::Image, MAX_ICON_DOWNLOAD_BYTES).await {
            Ok((_final_url, bytes)) => {
                if let Ok(png_bytes) = normalize_image_to_png(&bytes) {
                    return Ok(FetchedSiteIcon {
                        hostname,
                        png_bytes,
                    });
                }
            }

            Err(error) if error.is_security_boundary_error() => {
                return Err(error);
            }

            Err(_) => {}
        }
    }

    Err(SiteIconFetchError::NoIconFound)
}

fn normalize_hostname(input: &str) -> Result<String, SiteIconFetchError> {
    let trimmed = input.trim();

    if trimmed.is_empty()
        || trimmed != input
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('@')
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err(SiteIconFetchError::InvalidHostname);
    }

    let parsed = Url::parse(&format!("https://{trimmed}/"))
        .map_err(|_| SiteIconFetchError::InvalidHostname)?;

    if parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(SiteIconFetchError::InvalidHostname);
    }

    let hostname = parsed
        .host_str()
        .ok_or(SiteIconFetchError::InvalidHostname)?
        .to_ascii_lowercase();

    if hostname.parse::<IpAddr>().is_ok() {
        /*
         * LocalVault v1.1 intentionally accepts
         * public DNS names only for favicon
         * acquisition. Direct IP targets are not
         * required for password-manager site icons
         * and increase the SSRF attack surface.
         */
        return Err(SiteIconFetchError::UnsafeNetworkTarget);
    }

    if hostname.len() > 253
        || hostname.ends_with('.')
        || !hostname.contains('.')
        || is_reserved_hostname(&hostname)
    {
        return Err(SiteIconFetchError::UnsafeNetworkTarget);
    }

    if !hostname.split('.').all(valid_dns_label) {
        return Err(SiteIconFetchError::InvalidHostname);
    }

    Ok(hostname)
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_reserved_hostname(hostname: &str) -> bool {
    hostname == "localhost"
        || hostname.ends_with(".localhost")
        || hostname.ends_with(".local")
        || hostname.ends_with(".lan")
        || hostname.ends_with(".home")
        || hostname.ends_with(".internal")
        || hostname.ends_with(".test")
        || hostname.ends_with(".invalid")
        || hostname.ends_with(".example")
}

fn validate_remote_url(url: &Url) -> Result<String, SiteIconFetchError> {
    if url.scheme() != "https" {
        return Err(SiteIconFetchError::InsecureScheme);
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(SiteIconFetchError::InvalidRedirect);
    }

    if url.port_or_known_default() != Some(443) {
        return Err(SiteIconFetchError::UnsupportedPort);
    }

    let hostname = url.host_str().ok_or(SiteIconFetchError::InvalidHostname)?;

    normalize_hostname(hostname)
}

async fn resolve_public_address(hostname: &str) -> Result<SocketAddr, SiteIconFetchError> {
    let addresses = lookup_host((hostname, 443))
        .await
        .map_err(|_| SiteIconFetchError::DnsResolutionFailed)?;

    let mut selected = None;

    for address in addresses {
        if !is_public_ip(address.ip()) {
            /*
             * Reject the entire hostname if DNS
             * supplies even one private/special
             * destination. This deliberately fails
             * closed against mixed-answer rebinding
             * tricks.
             */
            return Err(SiteIconFetchError::UnsafeNetworkTarget);
        }

        if selected.is_none() {
            selected = Some(address);
        }
    }

    selected.ok_or(SiteIconFetchError::DnsResolutionFailed)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),

        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    if octets[0] == 0 || octets[0] == 10 || octets[0] == 127 || octets[0] >= 224 {
        return false;
    }

    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return false;
    }

    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }

    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return false;
    }

    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return false;
    }

    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return false;
    }

    if octets[0] == 192 && octets[1] == 168 {
        return false;
    }

    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }

    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return false;
    }

    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return false;
    }

    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();

    /*
     * Be intentionally conservative:
     * LocalVault accepts current global-unicast
     * 2000::/3 space and rejects local, multicast,
     * documentation and other special ranges.
     */
    if !(0x2000..=0x3fff).contains(&segments[0]) {
        return false;
    }

    /*
     * 2001:db8::/32 is documentation-only.
     */
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }

    true
}

fn build_pinned_client(hostname: &str, address: SocketAddr) -> Result<Client, SiteIconFetchError> {
    Client::builder()
        /*
         * Do not allow environment/system proxying
         * to bypass our DNS/IP validation.
         */
        .no_proxy()
        /*
         * Every redirect is inspected manually.
         */
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(USER_AGENT)
        /*
         * Pin this request to the exact address
         * that passed our public-IP validation.
         * TLS SNI/certificate validation still
         * uses the original DNS hostname.
         */
        .resolve(hostname, address)
        .build()
        .map_err(|_| SiteIconFetchError::RequestFailed)
}

async fn fetch_resource(
    mut url: Url,
    kind: ResourceKind,
    max_bytes: usize,
) -> Result<(Url, Vec<u8>), SiteIconFetchError> {
    for redirect_index in 0..=MAX_REDIRECTS {
        let hostname = validate_remote_url(&url)?;

        let address = resolve_public_address(&hostname).await?;

        let client = build_pinned_client(&hostname, address)?;

        let response = client
            .get(url.clone())
            .header(ACCEPT, kind.accept_header())
            .send()
            .await
            .map_err(|_| SiteIconFetchError::RequestFailed)?;

        if response.status().is_redirection() {
            if redirect_index == MAX_REDIRECTS {
                return Err(SiteIconFetchError::RedirectLimit);
            }

            let location = response
                .headers()
                .get(LOCATION)
                .ok_or(SiteIconFetchError::InvalidRedirect)?
                .to_str()
                .map_err(|_| SiteIconFetchError::InvalidRedirect)?;

            let next = url
                .join(location)
                .map_err(|_| SiteIconFetchError::InvalidRedirect)?;

            /*
             * Validate before the next request.
             * DNS is then independently resolved
             * and pinned on the next loop pass.
             */
            validate_remote_url(&next)?;

            url = next;

            continue;
        }

        if !response.status().is_success() {
            return Err(SiteIconFetchError::RequestFailed);
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .ok_or(SiteIconFetchError::UnexpectedContentType)?;

        if !kind.accepts_content_type(content_type) {
            return Err(SiteIconFetchError::UnexpectedContentType);
        }

        let bytes = read_limited_body(response, max_bytes).await?;

        return Ok((url, bytes));
    }

    Err(SiteIconFetchError::RedirectLimit)
}

async fn read_limited_body(
    mut response: Response,
    max_bytes: usize,
) -> Result<Vec<u8>, SiteIconFetchError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(SiteIconFetchError::ResponseTooLarge);
    }

    let capacity = response.content_length().unwrap_or(0).min(max_bytes as u64) as usize;

    let mut body = Vec::with_capacity(capacity);

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| SiteIconFetchError::RequestFailed)?
    {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or(SiteIconFetchError::ResponseTooLarge)?;

        if next_len > max_bytes {
            return Err(SiteIconFetchError::ResponseTooLarge);
        }

        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

fn discover_icon_urls(base_url: &Url, html: &str) -> Vec<Url> {
    let document = Html::parse_document(html);

    let selector = Selector::parse("link[rel][href]").expect("static favicon selector must parse");

    let mut result = Vec::new();
    let mut seen = HashSet::new();

    for element in document.select(&selector) {
        let value = element.value();

        let Some(rel) = value.attr("rel") else {
            continue;
        };

        if !rel.to_ascii_lowercase().contains("icon") {
            continue;
        }

        let Some(href) = value.attr("href") else {
            continue;
        };

        let href = href.trim();

        if href.is_empty() {
            continue;
        }

        let Ok(candidate) = base_url.join(href) else {
            continue;
        };

        /*
         * Do not downgrade icon discovery to HTTP.
         * Non-HTTPS candidates are simply ignored;
         * the secure /favicon.ico fallback remains.
         */
        if candidate.scheme() != "https" {
            continue;
        }

        let key = candidate.as_str().to_owned();

        if seen.insert(key) {
            result.push(candidate);
        }

        if result.len() >= MAX_ICON_CANDIDATES {
            break;
        }
    }

    result
}

fn normalize_image_to_png(bytes: &[u8]) -> Result<Vec<u8>, SiteIconFetchError> {
    let dimensions_reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| SiteIconFetchError::InvalidImage)?;

    let (width, height) = dimensions_reader
        .into_dimensions()
        .map_err(|_| SiteIconFetchError::InvalidImage)?;

    if width == 0
        || height == 0
        || width > MAX_IMAGE_DIMENSION
        || height > MAX_IMAGE_DIMENSION
        || u64::from(width).saturating_mul(u64::from(height)) > MAX_IMAGE_PIXELS
    {
        return Err(SiteIconFetchError::UnsafeImageDimensions);
    }

    let image = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| SiteIconFetchError::InvalidImage)?
        .decode()
        .map_err(|_| SiteIconFetchError::InvalidImage)?;

    let normalized = if width > TARGET_ICON_SIZE || height > TARGET_ICON_SIZE {
        image.thumbnail(TARGET_ICON_SIZE, TARGET_ICON_SIZE)
    } else {
        image
    };

    let mut output = Cursor::new(Vec::new());

    normalized
        .write_to(&mut output, ImageFormat::Png)
        .map_err(|_| SiteIconFetchError::InvalidImage)?;

    let png = output.into_inner();

    if png.len() > MAX_SITE_ICON_BYTES {
        return Err(SiteIconFetchError::NormalizedImageTooLarge);
    }

    Ok(png)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageBuffer, Rgba};

    fn sample_png(width: u32, height: u32) -> Vec<u8> {
        let image = DynamicImage::ImageRgba8(ImageBuffer::from_pixel(
            width,
            height,
            Rgba([32, 96, 220, 255]),
        ));

        let mut output = Cursor::new(Vec::new());

        image.write_to(&mut output, ImageFormat::Png).unwrap();

        output.into_inner()
    }

    #[test]
    fn hostname_is_normalized_to_lowercase() {
        assert_eq!(normalize_hostname("GitHub.COM").unwrap(), "github.com");
    }

    #[test]
    fn direct_ip_targets_are_rejected() {
        assert_eq!(
            normalize_hostname("8.8.8.8"),
            Err(SiteIconFetchError::UnsafeNetworkTarget)
        );

        assert_eq!(
            normalize_hostname("127.0.0.1"),
            Err(SiteIconFetchError::UnsafeNetworkTarget)
        );
    }

    #[test]
    fn local_and_reserved_hostnames_are_rejected() {
        for hostname in [
            "localhost",
            "router.local",
            "machine.lan",
            "service.internal",
            "example.test",
        ] {
            assert_eq!(
                normalize_hostname(hostname),
                Err(SiteIconFetchError::UnsafeNetworkTarget),
                "{hostname}"
            );
        }
    }

    #[test]
    fn malformed_hostnames_are_rejected() {
        for hostname in [
            "",
            " github.com",
            "github.com ",
            "github.com/path",
            "user@github.com",
            "github.com:8443",
            "-bad.example.com",
        ] {
            assert!(normalize_hostname(hostname).is_err(), "{hostname}");
        }
    }

    #[test]
    fn private_and_special_ipv4_addresses_are_rejected() {
        for ip in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();

            assert!(!is_public_ip(parsed), "{ip}");
        }
    }

    #[test]
    fn ordinary_public_ipv4_addresses_are_allowed() {
        for ip in ["1.1.1.1", "8.8.8.8", "93.184.216.34"] {
            let parsed: IpAddr = ip.parse().unwrap();

            assert!(is_public_ip(parsed), "{ip}");
        }
    }

    #[test]
    fn private_and_documentation_ipv6_addresses_are_rejected() {
        for ip in ["::1", "fe80::1", "fc00::1", "2001:db8::1"] {
            let parsed: IpAddr = ip.parse().unwrap();

            assert!(!is_public_ip(parsed), "{ip}");
        }
    }

    #[test]
    fn ordinary_global_ipv6_address_is_allowed() {
        let parsed: IpAddr = "2606:4700:4700::1111".parse().unwrap();

        assert!(is_public_ip(parsed));
    }

    #[test]
    fn remote_url_requires_https_and_standard_port() {
        let http = Url::parse("http://github.com/favicon.ico").unwrap();

        assert_eq!(
            validate_remote_url(&http),
            Err(SiteIconFetchError::InsecureScheme)
        );

        let alternate_port = Url::parse("https://github.com:8443/favicon.ico").unwrap();

        assert_eq!(
            validate_remote_url(&alternate_port,),
            Err(SiteIconFetchError::UnsupportedPort)
        );
    }

    #[test]
    fn html_icon_discovery_resolves_relative_https_urls() {
        let base = Url::parse("https://github.com/account").unwrap();

        let html = r#"
            <html>
              <head>
                <link rel="stylesheet" href="/style.css">
                <link rel="icon" href="/assets/favicon.png">
                <link rel="shortcut icon" href="https://cdn.github.com/icon.ico">
                <link rel="icon" href="http://insecure.example/icon.png">
              </head>
            </html>
        "#;

        let icons = discover_icon_urls(&base, html);

        assert_eq!(icons.len(), 2);

        assert_eq!(icons[0].as_str(), "https://github.com/assets/favicon.png");

        assert_eq!(icons[1].as_str(), "https://cdn.github.com/icon.ico");
    }

    #[test]
    fn valid_image_is_normalized_to_png() {
        let source = sample_png(128, 64);

        let normalized = normalize_image_to_png(&source).unwrap();

        assert!(normalized.starts_with(b"\x89PNG\r\n\x1a\n"));

        assert!(normalized.len() <= MAX_SITE_ICON_BYTES);

        let reader = ImageReader::new(Cursor::new(normalized.as_slice()))
            .with_guessed_format()
            .unwrap();

        let (width, height) = reader.into_dimensions().unwrap();

        assert!(width <= TARGET_ICON_SIZE);
        assert!(height <= TARGET_ICON_SIZE);
    }

    #[test]
    fn malformed_image_is_rejected() {
        assert_eq!(
            normalize_image_to_png(b"not-an-image",),
            Err(SiteIconFetchError::InvalidImage)
        );
    }
}
