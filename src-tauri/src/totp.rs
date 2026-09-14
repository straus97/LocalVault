use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use url::form_urlencoded;
use zeroize::{Zeroize, Zeroizing};

use localvault_core::vault::data::{
    TotpAlgorithm, TotpConfig, MAX_TOTP_PERIOD_SECONDS, MAX_TOTP_SECRET_BYTES,
    MIN_TOTP_SECRET_BYTES,
};

const DEFAULT_TOTP_DIGITS: u8 = 6;
const DEFAULT_TOTP_PERIOD_SECONDS: u32 = 30;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("TOTP input is empty")]
    EmptyInput,

    #[error("TOTP URI is invalid")]
    InvalidUri,

    #[error("OTP type is unsupported")]
    UnsupportedType,

    #[error("TOTP secret is missing")]
    MissingSecret,

    #[error("TOTP secret is invalid")]
    InvalidSecret,

    #[error("TOTP algorithm is invalid")]
    InvalidAlgorithm,

    #[error("TOTP digit count is invalid")]
    InvalidDigits,

    #[error("TOTP period is invalid")]
    InvalidPeriod,

    #[error("TOTP update is conflicting")]
    ConflictingUpdate,

    #[error("system time is invalid")]
    InvalidTime,

    #[error("stored TOTP configuration is invalid")]
    InvalidConfig,

    #[error("TOTP computation failed")]
    Computation,
}

pub struct GeneratedTotp {
    code: String,
    expires_at_ms: i64,
    period_seconds: u32,
    digits: u8,
}

impl GeneratedTotp {
    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn into_parts(mut self) -> (String, i64, u32, u8) {
        let code = std::mem::take(&mut self.code);

        (code, self.expires_at_ms, self.period_seconds, self.digits)
    }
}

impl Drop for GeneratedTotp {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

pub fn parse_totp_input(input: &str) -> Result<TotpConfig, TotpError> {
    let input = input.trim();

    if input.is_empty() {
        return Err(TotpError::EmptyInput);
    }

    let is_uri = input
        .as_bytes()
        .get(..10)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"otpauth://"));

    if is_uri {
        parse_totp_uri(input)
    } else {
        config_from_secret(
            input,
            TotpAlgorithm::Sha1,
            DEFAULT_TOTP_DIGITS,
            DEFAULT_TOTP_PERIOD_SECONDS,
        )
    }
}

fn parse_totp_uri(input: &str) -> Result<TotpConfig, TotpError> {
    if input.contains('#') {
        return Err(TotpError::InvalidUri);
    }

    let rest = input.get(10..).ok_or(TotpError::InvalidUri)?;

    let (type_and_label, query) = rest.split_once('?').ok_or(TotpError::InvalidUri)?;

    let (otp_type, label) = type_and_label
        .split_once('/')
        .ok_or(TotpError::InvalidUri)?;

    if !otp_type.eq_ignore_ascii_case("totp") {
        return Err(TotpError::UnsupportedType);
    }

    if label.is_empty() || query.is_empty() {
        return Err(TotpError::InvalidUri);
    }

    let mut secret: Option<Zeroizing<String>> = None;

    let mut algorithm: Option<TotpAlgorithm> = None;

    let mut digits: Option<u8> = None;

    let mut period: Option<u32> = None;

    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key.eq_ignore_ascii_case("secret") {
            if secret.is_some() {
                return Err(TotpError::InvalidUri);
            }

            secret = Some(Zeroizing::new(value.into_owned()));

            continue;
        }

        if key.eq_ignore_ascii_case("algorithm") {
            if algorithm.is_some() {
                return Err(TotpError::InvalidUri);
            }

            algorithm = Some(parse_algorithm(value.as_ref())?);

            continue;
        }

        if key.eq_ignore_ascii_case("digits") {
            if digits.is_some() {
                return Err(TotpError::InvalidUri);
            }

            digits = Some(value.parse::<u8>().map_err(|_| TotpError::InvalidDigits)?);

            continue;
        }

        if key.eq_ignore_ascii_case("period") {
            if period.is_some() {
                return Err(TotpError::InvalidUri);
            }

            period = Some(value.parse::<u32>().map_err(|_| TotpError::InvalidPeriod)?);
        }
    }

    let secret = secret.ok_or(TotpError::MissingSecret)?;

    config_from_secret(
        secret.as_str(),
        algorithm.unwrap_or(TotpAlgorithm::Sha1),
        digits.unwrap_or(DEFAULT_TOTP_DIGITS),
        period.unwrap_or(DEFAULT_TOTP_PERIOD_SECONDS),
    )
}

fn parse_algorithm(value: &str) -> Result<TotpAlgorithm, TotpError> {
    if value.eq_ignore_ascii_case("SHA1") {
        return Ok(TotpAlgorithm::Sha1);
    }

    if value.eq_ignore_ascii_case("SHA256") {
        return Ok(TotpAlgorithm::Sha256);
    }

    if value.eq_ignore_ascii_case("SHA512") {
        return Ok(TotpAlgorithm::Sha512);
    }

    Err(TotpError::InvalidAlgorithm)
}

fn config_from_secret(
    raw_secret: &str,
    algorithm: TotpAlgorithm,
    digits: u8,
    period_seconds: u32,
) -> Result<TotpConfig, TotpError> {
    validate_digits(digits)?;
    validate_period(period_seconds)?;

    let decoded = decode_base32_secret(raw_secret)?;

    Ok(TotpConfig {
        secret_base64: BASE64_STANDARD.encode(decoded.as_slice()),
        algorithm,
        digits,
        period_seconds,
    })
}

fn decode_base32_secret(raw_secret: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let compact = Zeroizing::new(
        raw_secret
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>(),
    );

    if compact.is_empty() {
        return Err(TotpError::InvalidSecret);
    }

    let without_padding = compact.trim_end_matches('=');

    if without_padding.is_empty() || without_padding.contains('=') {
        return Err(TotpError::InvalidSecret);
    }

    let normalized = Zeroizing::new(without_padding.to_ascii_uppercase());

    if !normalized
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
    {
        return Err(TotpError::InvalidSecret);
    }

    let decoded = Zeroizing::new(
        BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| TotpError::InvalidSecret)?,
    );

    if decoded.len() < MIN_TOTP_SECRET_BYTES || decoded.len() > MAX_TOTP_SECRET_BYTES {
        return Err(TotpError::InvalidSecret);
    }

    Ok(decoded)
}

fn validate_digits(digits: u8) -> Result<(), TotpError> {
    if matches!(digits, 6 | 8) {
        Ok(())
    } else {
        Err(TotpError::InvalidDigits)
    }
}

fn validate_period(period_seconds: u32) -> Result<(), TotpError> {
    if (1..=MAX_TOTP_PERIOD_SECONDS).contains(&period_seconds) {
        Ok(())
    } else {
        Err(TotpError::InvalidPeriod)
    }
}

pub fn generate_totp(config: &TotpConfig, now_ms: i64) -> Result<GeneratedTotp, TotpError> {
    if now_ms < 0 {
        return Err(TotpError::InvalidTime);
    }

    validate_digits(config.digits).map_err(|_| TotpError::InvalidConfig)?;

    validate_period(config.period_seconds).map_err(|_| TotpError::InvalidConfig)?;

    let secret = Zeroizing::new(
        BASE64_STANDARD
            .decode(config.secret_base64.as_bytes())
            .map_err(|_| TotpError::InvalidConfig)?,
    );

    if secret.len() < MIN_TOTP_SECRET_BYTES || secret.len() > MAX_TOTP_SECRET_BYTES {
        return Err(TotpError::InvalidConfig);
    }

    let now_ms = u64::try_from(now_ms).map_err(|_| TotpError::InvalidTime)?;

    let now_seconds = now_ms / 1_000;

    let period = u64::from(config.period_seconds);

    let counter = now_seconds / period;

    let message = counter.to_be_bytes();

    let digest = match config.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_slice())
                .map_err(|_| TotpError::Computation)?;

            mac.update(&message);

            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }

        TotpAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_slice())
                .map_err(|_| TotpError::Computation)?;

            mac.update(&message);

            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }

        TotpAlgorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret.as_slice())
                .map_err(|_| TotpError::Computation)?;

            mac.update(&message);

            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
    };

    let offset = usize::from(digest.last().copied().ok_or(TotpError::Computation)? & 0x0f);

    let window = digest
        .get(offset..offset + 4)
        .ok_or(TotpError::Computation)?;

    let binary = (u32::from(window[0] & 0x7f) << 24)
        | (u32::from(window[1]) << 16)
        | (u32::from(window[2]) << 8)
        | u32::from(window[3]);

    let modulus = 10_u32.pow(u32::from(config.digits));

    let value = binary % modulus;

    let code = format!("{value:0width$}", width = usize::from(config.digits),);

    let next_period_seconds = counter
        .checked_add(1)
        .and_then(|value| value.checked_mul(period))
        .ok_or(TotpError::InvalidTime)?;

    let expires_at_ms = next_period_seconds
        .checked_mul(1_000)
        .ok_or(TotpError::InvalidTime)?;

    let expires_at_ms = i64::try_from(expires_at_ms).map_err(|_| TotpError::InvalidTime)?;

    Ok(GeneratedTotp {
        code,
        expires_at_ms,
        period_seconds: config.period_seconds,
        digits: config.digits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(secret: &[u8], algorithm: TotpAlgorithm) -> TotpConfig {
        TotpConfig {
            secret_base64: BASE64_STANDARD.encode(secret),
            algorithm,
            digits: 8,
            period_seconds: 30,
        }
    }

    #[test]
    fn bare_base32_uses_standard_defaults() {
        let parsed = parse_totp_input("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();

        assert_eq!(parsed.algorithm, TotpAlgorithm::Sha1,);

        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period_seconds, 30);
    }

    #[test]
    fn otpauth_uri_parses_supported_parameters() {
        let parsed =
            parse_totp_input(
                "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=45&issuer=Example",
            )
            .unwrap();

        assert_eq!(parsed.algorithm, TotpAlgorithm::Sha256,);

        assert_eq!(parsed.digits, 8);
        assert_eq!(parsed.period_seconds, 45);
    }

    #[test]
    fn hotp_uri_is_rejected() {
        let result = parse_totp_input(
            "otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1",
        );

        assert!(matches!(result, Err(TotpError::UnsupportedType)));
    }

    #[test]
    fn rfc_6238_sha1_vector_matches() {
        let generated = generate_totp(
            &config(b"12345678901234567890", TotpAlgorithm::Sha1),
            59_000,
        )
        .unwrap();

        assert_eq!(generated.code(), "94287082",);
    }

    #[test]
    fn rfc_6238_sha256_vector_matches() {
        let generated = generate_totp(
            &config(b"12345678901234567890123456789012", TotpAlgorithm::Sha256),
            59_000,
        )
        .unwrap();

        assert_eq!(generated.code(), "46119246",);
    }

    #[test]
    fn rfc_6238_sha512_vector_matches() {
        let generated = generate_totp(
            &config(
                b"1234567890123456789012345678901234567890123456789012345678901234",
                TotpAlgorithm::Sha512,
            ),
            59_000,
        )
        .unwrap();

        assert_eq!(generated.code(), "90693936",);
    }

    #[test]
    fn six_digit_code_is_zero_padded() {
        let mut config = config(b"12345678901234567890", TotpAlgorithm::Sha1);

        config.digits = 6;

        let generated = generate_totp(&config, 59_000).unwrap();

        assert_eq!(generated.code(), "287082",);
    }
}
