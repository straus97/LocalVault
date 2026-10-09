//! Platform-neutral site identity derived from an entry URL.
//!
//! A *site key* is a derived, non-persisted grouping identity: the normalized
//! hostname of an entry's URL. Nothing here is stored in `VaultData`, touches
//! the network, reads a clock or depends on any platform. Adapters use it to
//! group entries (one site, many profiles/accounts) in their own UI.

use url::{Host, Url};

/// Normalized site key for an entry URL, or `None` when the value has no
/// usable host (blank, unparseable, or a host-less scheme such as `file:///x`).
///
/// Contract:
/// - the input is trimmed; blank input is `None`;
/// - a value that starts with `<scheme>://` is parsed as-is; any other value
///   is treated as a scheme-less, host-like value (`example.com`,
///   `www.example.com/path`, `example.com:8080`) and parsed as `https://<value>`.
///   This mirrors how desktop already treats entry URLs;
/// - an explicit `<scheme>://` must be followed by a non-empty authority: if
///   the text right after `://` starts with `/` (or `\`) the value is `None`
///   (`http:///path`, `https:////example.com`, `file:///x`), even though the
///   URL parser alone would repair some of these into a host;
/// - the key is the host only: scheme, userinfo, port, path, query and
///   fragment never contribute;
/// - lowercased; one trailing root dot is removed; exactly one leading `www.`
///   is removed (`www.www.a.com` -> `www.a.com`); every other subdomain is
///   preserved (`accounts.a.com` stays distinct from `a.com`);
/// - IP-literal hosts are kept as-is (IPv6 in brackets) and never `www.`-stripped;
/// - no fallback identity is invented: unparseable input is `None`.
pub fn site_key(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parsed = if has_explicit_scheme(trimmed) {
        // `url` repairs `http:///path` into host `path`; an explicit scheme
        // whose authority is empty is malformed, not a site.
        if explicit_authority_is_empty(trimmed) {
            return None;
        }
        Url::parse(trimmed).ok()?
    } else {
        Url::parse(&format!("https://{trimmed}")).ok()?
    };

    match parsed.host()? {
        Host::Domain(domain) => normalize_domain(domain),
        Host::Ipv4(address) => Some(address.to_string()),
        Host::Ipv6(address) => Some(format!("[{address}]")),
    }
}

/// `^[a-z][a-z0-9+.-]*://` (case-insensitive), the same test desktop uses to
/// decide whether a value already carries a scheme.
fn has_explicit_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

/// For a value that has `<scheme>://`: true when the text right after `://`
/// starts with `/` (or `\`, which the URL parser treats as `/` for special
/// schemes), i.e. there is no authority before the path.
fn explicit_authority_is_empty(value: &str) -> bool {
    value
        .split_once("://")
        .is_some_and(|(_, rest)| rest.starts_with(['/', '\\']))
}

fn normalize_domain(domain: &str) -> Option<String> {
    let lowered = domain.to_ascii_lowercase();
    let without_root_dot = lowered.strip_suffix('.').unwrap_or(&lowered);
    let host = without_root_dot
        .strip_prefix("www.")
        .unwrap_or(without_root_dot);

    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::site_key;

    fn key(input: &str) -> Option<String> {
        site_key(input)
    }

    fn some(value: &str) -> Option<String> {
        Some(value.to_owned())
    }

    #[test]
    fn host_is_lowercased() {
        assert_eq!(key("https://GitHub.COM/Login"), some("github.com"));
        assert_eq!(key("HTTPS://EXAMPLE.org"), some("example.org"));
    }

    #[test]
    fn exactly_one_leading_www_is_removed() {
        assert_eq!(key("https://www.example.com"), some("example.com"));
        assert_eq!(key("https://WWW.Example.com"), some("example.com"));
        assert_eq!(key("https://www.www.example.com"), some("www.example.com"));
        // "www" is only a prefix when followed by a dot.
        assert_eq!(key("https://wwwexample.com"), some("wwwexample.com"));
        // A bare "www" host has nothing after the prefix to strip down to.
        assert_eq!(key("http://www/"), some("www"));
        assert_eq!(key("http://www./"), some("www"));
    }

    #[test]
    fn path_query_and_fragment_are_ignored() {
        assert_eq!(key("https://example.com/a/b?x=1#frag"), some("example.com"));
        assert_eq!(key("https://example.com?x=1"), some("example.com"));
        assert_eq!(key("https://example.com#frag"), some("example.com"));
    }

    #[test]
    fn port_scheme_and_userinfo_are_not_part_of_the_key() {
        assert_eq!(key("https://example.com:8443/x"), some("example.com"));
        assert_eq!(key("http://example.com:80"), some("example.com"));
        assert_eq!(key("http://example.com"), some("example.com"));
        assert_eq!(key("https://user:pw@example.com/"), some("example.com"));
    }

    #[test]
    fn meaningful_subdomains_are_preserved() {
        assert_eq!(
            key("https://accounts.example.com/signin"),
            some("accounts.example.com")
        );
        assert_eq!(
            key("https://www.accounts.example.com"),
            some("accounts.example.com")
        );
        assert_ne!(key("https://a.example.com"), key("https://example.com"));
    }

    #[test]
    fn www_variants_and_plain_host_share_one_key() {
        let plain = key("https://example.com/login");
        assert_eq!(plain, key("http://www.example.com"));
        assert_eq!(plain, key("example.com"));
        assert_eq!(plain, key("WWW.EXAMPLE.COM/other?x=1"));
    }

    #[test]
    fn one_trailing_root_dot_is_removed() {
        assert_eq!(key("https://example.com./x"), some("example.com"));
        assert_eq!(key("https://www.example.com."), some("example.com"));
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(key("  https://example.com  "), some("example.com"));
        assert_eq!(key("\texample.com\n"), some("example.com"));
    }

    #[test]
    fn blank_input_has_no_key() {
        assert_eq!(key(""), None);
        assert_eq!(key("   "), None);
        assert_eq!(key("\t\n"), None);
    }

    #[test]
    fn malformed_input_has_no_key() {
        for input in [
            "https://",
            "https://exa mple.com",
            "https://exa%mple.com",
            "not a url",
            "://example.com",
            "https://[::1",
            "https://.",
        ] {
            assert_eq!(key(input), None, "{input:?}");
        }
    }

    #[test]
    fn empty_explicit_authority_is_not_repaired_into_a_site() {
        assert_eq!(key("http:///path"), None);
        assert_eq!(key("https:////example.com"), None);
        assert_eq!(key("HTTP:///path"), None);
        assert_eq!(key("ftp:///files.example.com/pub"), None);
        // The well-formed counterparts still work.
        assert_eq!(key("http://path"), some("path"));
        assert_eq!(key("https://example.com"), some("example.com"));
    }

    #[test]
    fn host_less_schemes_have_no_key() {
        assert_eq!(key("file:///etc/passwd"), None);
        assert_eq!(key("data://"), None);
    }

    #[test]
    fn scheme_less_host_like_values_are_accepted() {
        assert_eq!(key("example.com"), some("example.com"));
        assert_eq!(key("www.example.com/path"), some("example.com"));
        assert_eq!(key("Example.com?x=1"), some("example.com"));
        assert_eq!(
            key("accounts.example.com/signin#a"),
            some("accounts.example.com")
        );
    }

    #[test]
    fn scheme_less_value_with_port_is_not_mistaken_for_a_scheme() {
        // `url` alone would parse "example.com:8080/x" as scheme "example.com".
        assert_eq!(key("example.com:8080/x"), some("example.com"));
        assert_eq!(key("www.example.com:8080"), some("example.com"));
        assert_eq!(key("localhost:3000/app"), some("localhost"));
    }

    #[test]
    fn localhost_is_a_valid_key() {
        assert_eq!(key("http://localhost:3000/app"), some("localhost"));
        assert_eq!(key("localhost"), some("localhost"));
        assert_eq!(key("http://LOCALHOST"), some("localhost"));
    }

    #[test]
    fn ip_addresses_are_kept_and_never_www_stripped() {
        assert_eq!(key("http://192.168.1.10:8080/admin"), some("192.168.1.10"));
        assert_eq!(key("192.168.1.10"), some("192.168.1.10"));
        assert_eq!(key("https://127.0.0.1"), some("127.0.0.1"));
        assert_eq!(key("http://[::1]:8080/x"), some("[::1]"));
        assert_eq!(key("http://[2001:DB8::1]/"), some("[2001:db8::1]"));
    }

    #[test]
    fn internationalized_hosts_use_a_stable_ascii_form() {
        let punycode = key("https://пример.рф/вход");
        assert_eq!(punycode, some("xn--e1afmkfd.xn--p1ai"));
        assert_eq!(punycode, key("https://ПРИМЕР.РФ"));
        assert_eq!(punycode, key("пример.рф"));
    }

    #[test]
    fn explicit_non_http_schemes_with_a_host_are_host_based() {
        assert_eq!(
            key("ftp://Files.Example.com/pub"),
            some("files.example.com")
        );
    }

    #[test]
    fn result_is_deterministic() {
        let input = "https://WWW.Example.com:8443/a?b=c#d";
        assert_eq!(key(input), key(input));
    }
}
