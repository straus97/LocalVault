use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroize;

pub const MIN_GENERATED_PASSWORD_LENGTH: usize = 12;
pub const MAX_GENERATED_PASSWORD_LENGTH: usize = 128;
pub const DEFAULT_GENERATED_PASSWORD_LENGTH: usize = 20;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordGeneratorOptions {
    pub length: usize,
    pub include_lowercase: bool,
    pub include_uppercase: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: DEFAULT_GENERATED_PASSWORD_LENGTH,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordGeneratorError {
    #[error("generated password length is invalid")]
    InvalidLength,

    #[error("at least one character class is required")]
    NoCharacterClasses,

    #[error("password length is too small for selected classes")]
    LengthTooShort,

    #[error("secure system randomness is unavailable")]
    Randomness,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPassword {
    pub password: String,
}

impl Drop for GeneratedPassword {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub fn generate_password(
    options: PasswordGeneratorOptions,
) -> Result<GeneratedPassword, PasswordGeneratorError> {
    if !(MIN_GENERATED_PASSWORD_LENGTH..=MAX_GENERATED_PASSWORD_LENGTH).contains(&options.length) {
        return Err(PasswordGeneratorError::InvalidLength);
    }

    let groups = selected_groups(options);

    if groups.is_empty() {
        return Err(PasswordGeneratorError::NoCharacterClasses);
    }

    if options.length < groups.len() {
        return Err(PasswordGeneratorError::LengthTooShort);
    }

    let mut bytes = Vec::with_capacity(options.length);

    /*
     * Guarantee at least one character from every selected
     * character class.
     */
    for group in &groups {
        bytes.push(group[sample_index(group.len())?]);
    }

    let alphabet: Vec<u8> = groups
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect();

    while bytes.len() < options.length {
        bytes.push(alphabet[sample_index(alphabet.len())?]);
    }

    /*
     * Fisher-Yates also uses unbiased indices.
     */
    secure_shuffle(&mut bytes)?;

    let password = String::from_utf8(bytes).expect("password generator uses ASCII only");

    Ok(GeneratedPassword { password })
}

fn selected_groups(options: PasswordGeneratorOptions) -> Vec<&'static [u8]> {
    let mut groups = Vec::with_capacity(4);

    if options.include_lowercase {
        groups.push(LOWERCASE);
    }

    if options.include_uppercase {
        groups.push(UPPERCASE);
    }

    if options.include_digits {
        groups.push(DIGITS);
    }

    if options.include_symbols {
        groups.push(SYMBOLS);
    }

    groups
}

fn secure_shuffle(values: &mut [u8]) -> Result<(), PasswordGeneratorError> {
    for index in (1..values.len()).rev() {
        let swap_with = sample_index(index + 1)?;
        values.swap(index, swap_with);
    }

    Ok(())
}

fn sample_index(bound: usize) -> Result<usize, PasswordGeneratorError> {
    debug_assert!(bound > 0);

    let bound = u32::try_from(bound).map_err(|_| PasswordGeneratorError::InvalidLength)?;

    /*
     * Rejection sampling removes modulo bias.
     */
    let threshold = bound.wrapping_neg() % bound;

    loop {
        let value = random_u32()?;

        if value >= threshold {
            return Ok((value % bound) as usize);
        }
    }
}

fn random_u32() -> Result<u32, PasswordGeneratorError> {
    let mut bytes = [0_u8; 4];

    getrandom::fill(&mut bytes).map_err(|_| PasswordGeneratorError::Randomness)?;

    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains_any(value: &str, group: &[u8]) -> bool {
        value.bytes().any(|byte| group.contains(&byte))
    }

    #[test]
    fn length_bounds_are_enforced() {
        let too_short = PasswordGeneratorOptions {
            length: MIN_GENERATED_PASSWORD_LENGTH - 1,
            ..PasswordGeneratorOptions::default()
        };

        assert!(matches!(
            generate_password(too_short),
            Err(PasswordGeneratorError::InvalidLength)
        ));

        let too_long = PasswordGeneratorOptions {
            length: MAX_GENERATED_PASSWORD_LENGTH + 1,
            ..PasswordGeneratorOptions::default()
        };

        assert!(matches!(
            generate_password(too_long),
            Err(PasswordGeneratorError::InvalidLength)
        ));
    }

    #[test]
    fn at_least_one_character_class_is_required() {
        let options = PasswordGeneratorOptions {
            length: 20,
            include_lowercase: false,
            include_uppercase: false,
            include_digits: false,
            include_symbols: false,
        };

        assert!(matches!(
            generate_password(options),
            Err(PasswordGeneratorError::NoCharacterClasses)
        ));
    }

    #[test]
    fn generated_password_has_requested_length_and_selected_classes() {
        let generated = generate_password(PasswordGeneratorOptions {
            length: 64,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
        })
        .unwrap();

        assert_eq!(generated.password.chars().count(), 64);
        assert!(contains_any(&generated.password, LOWERCASE));
        assert!(contains_any(&generated.password, UPPERCASE));
        assert!(contains_any(&generated.password, DIGITS));
        assert!(contains_any(&generated.password, SYMBOLS));
    }

    #[test]
    fn generated_password_excludes_unselected_classes() {
        let generated = generate_password(PasswordGeneratorOptions {
            length: 32,
            include_lowercase: false,
            include_uppercase: false,
            include_digits: true,
            include_symbols: false,
        })
        .unwrap();

        assert_eq!(generated.password.chars().count(), 32);

        assert!(generated
            .password
            .bytes()
            .all(|byte| DIGITS.contains(&byte)));
    }
}
