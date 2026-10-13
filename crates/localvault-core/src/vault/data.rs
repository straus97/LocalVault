use std::{collections::HashSet, net::IpAddr};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{
    de::Error as _, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer,
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const LEGACY_VAULT_DATA_SCHEMA_VERSION: u16 = 1;

/// Schema 2 added encrypted TOTP configuration. It predates the authenticated
/// revision counter, so a schema-2 payload carries no `revision` field and has
/// an effective revision of 0.
pub const PRE_REVISION_VAULT_DATA_SCHEMA_VERSION: u16 = 2;

/// Schema 3 adds the authenticated `revision` counter (Stage 1U-2).
pub const VAULT_DATA_SCHEMA_VERSION: u16 = 3;

pub const MAX_ENTRIES: usize = 50_000;
pub const MAX_CATEGORIES: usize = 512;
pub const MAX_SITE_ICONS: usize = 512;

pub const MAX_SITE_ICON_HOSTNAME_CHARS: usize = 253;
pub const MAX_SITE_ICON_BYTES: usize = 256 * 1024;
pub const MAX_TOTAL_SITE_ICON_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SITE_ICON_BASE64_CHARS: usize = MAX_SITE_ICON_BYTES.div_ceil(3) * 4;

pub const MAX_TITLE_CHARS: usize = 256;
pub const MAX_PROFILE_NAME_CHARS: usize = 128;
pub const MAX_USERNAME_CHARS: usize = 1_024;
pub const MAX_PASSWORD_CHARS: usize = 16_384;
pub const MAX_URL_CHARS: usize = 4_096;
pub const MAX_NOTES_CHARS: usize = 262_144;

pub const MIN_TOTP_SECRET_BYTES: usize = 10;
pub const MAX_TOTP_SECRET_BYTES: usize = 128;
pub const MAX_TOTP_SECRET_BASE64_CHARS: usize = MAX_TOTP_SECRET_BYTES.div_ceil(3) * 4;
pub const MAX_TOTP_PERIOD_SECONDS: u32 = 300;

pub const MAX_CATEGORY_NAME_CHARS: usize = 128;
pub const MAX_TAGS_PER_ENTRY: usize = 64;
pub const MAX_TAG_CHARS: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultDataError {
    #[error("unsupported vault data schema version")]
    UnsupportedSchemaVersion,

    #[error("vault revision metadata is invalid")]
    InvalidRevision,

    #[error("vault revision counter cannot be incremented further")]
    RevisionOverflow,

    #[error("vault id must not be nil")]
    NilVaultId,

    #[error("entry id must not be nil")]
    NilEntryId,

    #[error("category id must not be nil")]
    NilCategoryId,

    #[error("vault contains too many entries")]
    TooManyEntries,

    #[error("vault contains too many categories")]
    TooManyCategories,

    #[error("vault contains too many cached site icons")]
    TooManySiteIcons,

    #[error("duplicate cached site icon hostname")]
    DuplicateSiteIconHostname,

    #[error("cached site icon hostname is invalid")]
    InvalidSiteIconHostname,

    #[error("cached site icon data is empty")]
    EmptySiteIconData,

    #[error("cached site icon data is too large")]
    SiteIconDataTooLarge,

    #[error("cached site icon data is not valid base64")]
    InvalidSiteIconBase64,

    #[error("cached site icon is not normalized PNG data")]
    InvalidSiteIconPng,

    #[error("total cached site icon data is too large")]
    TotalSiteIconDataTooLarge,

    #[error("cached site icon timestamp is invalid")]
    InvalidSiteIconTimestamp,

    #[error("duplicate entry id")]
    DuplicateEntryId(Uuid),

    #[error("duplicate category id")]
    DuplicateCategoryId(Uuid),

    #[error("entry references an unknown category")]
    UnknownCategory(Uuid),

    #[error("entry title must not be empty")]
    EmptyEntryTitle(Uuid),

    #[error("entry title is too long")]
    EntryTitleTooLong(Uuid),

    #[error("entry profile name is too long")]
    EntryProfileNameTooLong(Uuid),

    #[error("entry username is too long")]
    EntryUsernameTooLong(Uuid),

    #[error("entry password is too long")]
    EntryPasswordTooLong(Uuid),

    #[error("legacy vault schema contains TOTP data")]
    LegacySchemaContainsTotp(Uuid),

    #[error("entry TOTP secret is invalid")]
    InvalidTotpSecret(Uuid),

    #[error("entry TOTP settings are invalid")]
    InvalidTotpSettings(Uuid),

    #[error("entry URL is too long")]
    EntryUrlTooLong(Uuid),

    #[error("entry notes are too long")]
    EntryNotesTooLong(Uuid),

    #[error("entry contains too many tags")]
    TooManyTags(Uuid),

    #[error("entry contains an empty tag")]
    EmptyTag(Uuid),

    #[error("entry tag is too long")]
    TagTooLong(Uuid),

    #[error("entry contains a duplicate tag")]
    DuplicateTag(Uuid),

    #[error("category name must not be empty")]
    EmptyCategoryName(Uuid),

    #[error("category name is too long")]
    CategoryNameTooLong(Uuid),

    #[error("vault timestamp is invalid")]
    InvalidVaultTimestamp,

    #[error("entry timestamp is invalid")]
    InvalidEntryTimestamp(Uuid),

    #[error("category timestamp is invalid")]
    InvalidCategoryTimestamp(Uuid),
}

/// The decrypted vault payload.
///
/// `revision` counts committed logical payload writes. It lives inside the
/// encrypted payload, so it is authenticated by the payload AEAD. It is only
/// serialized for schema 3 and later; legacy payloads (schema 1 and 2) have no
/// such field and read as revision 0. Serialization and deserialization are
/// therefore schema-aware and implemented by hand below.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultData {
    pub schema_version: u16,
    pub vault_id: Uuid,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub entries: Vec<VaultEntry>,
    pub categories: Vec<VaultCategory>,
    pub site_icons: Vec<SiteIcon>,
    pub revision: u64,
}

/// Wire shape of [`VaultData`] used only for deserialization.
///
/// `revision` is `None` only when the key is absent. A present key must be a
/// genuine unsigned integer: `deserialize_with` forces `u64` parsing, so
/// `null`, a string, a negative or a fractional number is a parse error rather
/// than being silently read as "absent".
#[derive(Deserialize)]
struct VaultDataWire {
    schema_version: u16,
    vault_id: Uuid,
    created_at_ms: i64,
    updated_at_ms: i64,
    entries: Vec<VaultEntry>,
    categories: Vec<VaultCategory>,
    #[serde(default)]
    site_icons: Vec<SiteIcon>,
    #[serde(default, deserialize_with = "present_revision")]
    revision: Option<u64>,
}

fn present_revision<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    u64::deserialize(deserializer).map(Some)
}

impl<'de> Deserialize<'de> for VaultData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = VaultDataWire::deserialize(deserializer)?;

        let revision = match (wire.schema_version, wire.revision) {
            // Legacy payloads predate the counter.
            (LEGACY_VAULT_DATA_SCHEMA_VERSION, None)
            | (PRE_REVISION_VAULT_DATA_SCHEMA_VERSION, None) => 0,
            // No LocalVault writer ever produced a revision in a legacy
            // payload, so one is malformed metadata, not a harmless extra.
            (LEGACY_VAULT_DATA_SCHEMA_VERSION, Some(_))
            | (PRE_REVISION_VAULT_DATA_SCHEMA_VERSION, Some(_)) => {
                return Err(D::Error::custom(VaultDataError::InvalidRevision));
            }
            // Schema 3 must state its revision explicitly.
            (VAULT_DATA_SCHEMA_VERSION, Some(revision)) => revision,
            (VAULT_DATA_SCHEMA_VERSION, None) => {
                return Err(D::Error::custom(VaultDataError::InvalidRevision));
            }
            // Unsupported (future or zero) schemas are not interpreted here;
            // `validate` rejects them, preserving the existing error class.
            (_, revision) => revision.unwrap_or(0),
        };

        Ok(Self {
            schema_version: wire.schema_version,
            vault_id: wire.vault_id,
            created_at_ms: wire.created_at_ms,
            updated_at_ms: wire.updated_at_ms,
            entries: wire.entries,
            categories: wire.categories,
            site_icons: wire.site_icons,
            revision,
        })
    }
}

impl Serialize for VaultData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let has_site_icons = !self.site_icons.is_empty();
        let has_revision = self.schema_version >= VAULT_DATA_SCHEMA_VERSION;

        let field_count = 6 + usize::from(has_site_icons) + usize::from(has_revision);

        let mut state = serializer.serialize_struct("VaultData", field_count)?;

        state.serialize_field("schema_version", &self.schema_version)?;
        state.serialize_field("vault_id", &self.vault_id)?;
        state.serialize_field("created_at_ms", &self.created_at_ms)?;
        state.serialize_field("updated_at_ms", &self.updated_at_ms)?;
        state.serialize_field("entries", &self.entries)?;
        state.serialize_field("categories", &self.categories)?;

        if has_site_icons {
            state.serialize_field("site_icons", &self.site_icons)?;
        }

        // Legacy schemas never carried a revision; omitting it keeps a
        // serialized legacy payload identical in shape to what older
        // builds wrote.
        if has_revision {
            state.serialize_field("revision", &self.revision)?;
        }

        state.end()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteIcon {
    pub hostname: String,
    pub png_base64: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TotpAlgorithm {
    #[serde(rename = "SHA1")]
    Sha1,

    #[serde(rename = "SHA256")]
    Sha256,

    #[serde(rename = "SHA512")]
    Sha512,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpConfig {
    pub secret_base64: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period_seconds: u32,
}

impl TotpConfig {
    pub(crate) fn zeroize_sensitive_fields(&mut self) {
        self.secret_base64.zeroize();
    }
}

impl Drop for TotpConfig {
    fn drop(&mut self) {
        self.zeroize_sensitive_fields();
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEntry {
    pub id: Uuid,
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile_name: String,
    pub url: String,
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpConfig>,
    pub notes: String,
    pub category_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultCategory {
    pub id: Uuid,
    pub name: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl VaultData {
    pub fn new(now_ms: i64) -> Result<Self, VaultDataError> {
        if now_ms < 0 {
            return Err(VaultDataError::InvalidVaultTimestamp);
        }

        Ok(Self {
            schema_version: VAULT_DATA_SCHEMA_VERSION,
            vault_id: Uuid::new_v4(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            entries: Vec::new(),
            categories: Vec::new(),
            site_icons: Vec::new(),
            revision: 0,
        })
    }

    /// Upgrade an in-memory legacy (schema 1 or 2) vault to the current
    /// schema. A no-op if the vault is already current.
    ///
    /// This is the schema step only: it never touches `revision`. It exists so
    /// an adapter can validate a TOTP-bearing candidate (schema 1 cannot carry
    /// TOTP) *before* [`prepare_for_write`](Self::prepare_for_write). Every
    /// persisted write must still go through `prepare_for_write`.
    pub fn upgrade_legacy_schema(&mut self) {
        if self.schema_version == LEGACY_VAULT_DATA_SCHEMA_VERSION
            || self.schema_version == PRE_REVISION_VAULT_DATA_SCHEMA_VERSION
        {
            self.schema_version = VAULT_DATA_SCHEMA_VERSION;
        }
    }

    /// The single, shared write-preparation rule (see
    /// `@docs/SECURITY_MODEL.md`). Every adapter that persists a mutated
    /// `VaultData` (desktop and Android) must call this exactly once on the
    /// *candidate* it is about to seal, never on the committed data.
    ///
    /// It upgrades a legacy schema to the current one, advances `revision` by
    /// exactly one with a checked increment, and validates the result.
    ///
    /// Failure-atomic: on any error `self` is left exactly as it was passed in
    /// (schema and revision included), and a revision at `u64::MAX` is reported
    /// as [`VaultDataError::RevisionOverflow`] rather than wrapping.
    pub fn prepare_for_write(&mut self) -> Result<(), VaultDataError> {
        let original_schema = self.schema_version;
        let original_revision = self.revision;

        if !is_supported_schema(original_schema) {
            return Err(VaultDataError::UnsupportedSchemaVersion);
        }

        let next_revision = original_revision
            .checked_add(1)
            .ok_or(VaultDataError::RevisionOverflow)?;

        self.upgrade_legacy_schema();
        self.revision = next_revision;

        if let Err(error) = self.validate() {
            self.schema_version = original_schema;
            self.revision = original_revision;

            return Err(error);
        }

        Ok(())
    }

    pub fn validate(&self) -> Result<(), VaultDataError> {
        if !is_supported_schema(self.schema_version) {
            return Err(VaultDataError::UnsupportedSchemaVersion);
        }

        // Legacy schemas have no revision field, so a non-zero value could not
        // be persisted faithfully.
        if self.schema_version < VAULT_DATA_SCHEMA_VERSION && self.revision != 0 {
            return Err(VaultDataError::InvalidRevision);
        }

        if self.vault_id.is_nil() {
            return Err(VaultDataError::NilVaultId);
        }

        if !valid_timestamps(self.created_at_ms, self.updated_at_ms) {
            return Err(VaultDataError::InvalidVaultTimestamp);
        }

        if self.entries.len() > MAX_ENTRIES {
            return Err(VaultDataError::TooManyEntries);
        }

        if self.categories.len() > MAX_CATEGORIES {
            return Err(VaultDataError::TooManyCategories);
        }

        if self.site_icons.len() > MAX_SITE_ICONS {
            return Err(VaultDataError::TooManySiteIcons);
        }

        let mut site_icon_hostnames = HashSet::with_capacity(self.site_icons.len());

        let mut total_site_icon_bytes = 0usize;

        for site_icon in &self.site_icons {
            let icon_bytes = validate_site_icon(site_icon)?;

            if !site_icon_hostnames.insert(site_icon.hostname.as_str()) {
                return Err(VaultDataError::DuplicateSiteIconHostname);
            }

            total_site_icon_bytes = total_site_icon_bytes.saturating_add(icon_bytes);

            if total_site_icon_bytes > MAX_TOTAL_SITE_ICON_BYTES {
                return Err(VaultDataError::TotalSiteIconDataTooLarge);
            }
        }

        let mut category_ids = HashSet::with_capacity(self.categories.len());

        for category in &self.categories {
            validate_category(category)?;

            if !category_ids.insert(category.id) {
                return Err(VaultDataError::DuplicateCategoryId(category.id));
            }
        }

        let mut entry_ids = HashSet::with_capacity(self.entries.len());

        for entry in &self.entries {
            if self.schema_version == LEGACY_VAULT_DATA_SCHEMA_VERSION && entry.totp.is_some() {
                return Err(VaultDataError::LegacySchemaContainsTotp(entry.id));
            }

            validate_entry(entry, &category_ids)?;

            if !entry_ids.insert(entry.id) {
                return Err(VaultDataError::DuplicateEntryId(entry.id));
            }
        }

        Ok(())
    }
}

impl VaultData {
    pub(crate) fn zeroize_sensitive_fields(&mut self) {
        for site_icon in &mut self.site_icons {
            site_icon.zeroize_sensitive_fields();
        }

        for entry in &mut self.entries {
            entry.title.zeroize();
            entry.profile_name.zeroize();
            entry.url.zeroize();
            entry.username.zeroize();
            entry.password.zeroize();

            if let Some(totp) = entry.totp.as_mut() {
                totp.zeroize_sensitive_fields();
            }

            entry.totp = None;
            entry.notes.zeroize();

            for tag in &mut entry.tags {
                tag.zeroize();
            }

            entry.tags.clear();
        }

        for category in &mut self.categories {
            category.name.zeroize();
        }

        self.entries.clear();
        self.categories.clear();
        self.site_icons.clear();
    }
}
impl Drop for VaultData {
    fn drop(&mut self) {
        self.zeroize_sensitive_fields();
    }
}
impl SiteIcon {
    pub(crate) fn zeroize_sensitive_fields(&mut self) {
        self.hostname.zeroize();
        self.png_base64.zeroize();
    }
}

impl Drop for SiteIcon {
    fn drop(&mut self) {
        self.zeroize_sensitive_fields();
    }
}

impl VaultEntry {
    pub(crate) fn zeroize_sensitive_fields(&mut self) {
        self.title.zeroize();
        self.profile_name.zeroize();
        self.url.zeroize();
        self.username.zeroize();
        self.password.zeroize();

        if let Some(totp) = self.totp.as_mut() {
            totp.zeroize_sensitive_fields();
        }

        self.totp = None;
        self.notes.zeroize();

        for tag in &mut self.tags {
            tag.zeroize();
        }

        self.tags.clear();
    }
}

impl Drop for VaultEntry {
    fn drop(&mut self) {
        self.zeroize_sensitive_fields();
    }
}

impl VaultCategory {
    pub(crate) fn zeroize_sensitive_fields(&mut self) {
        self.name.zeroize();
    }
}

impl Drop for VaultCategory {
    fn drop(&mut self) {
        self.zeroize_sensitive_fields();
    }
}
impl VaultEntry {
    pub fn new(title: impl Into<String>, now_ms: i64) -> Result<Self, VaultDataError> {
        if now_ms < 0 {
            return Err(VaultDataError::InvalidEntryTimestamp(Uuid::nil()));
        }

        let entry = Self {
            id: Uuid::new_v4(),
            title: title.into(),
            profile_name: String::new(),
            url: String::new(),
            username: String::new(),
            password: String::new(),
            totp: None,
            notes: String::new(),
            category_id: None,
            tags: Vec::new(),
            favorite: false,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };

        if entry.title.trim().is_empty() {
            return Err(VaultDataError::EmptyEntryTitle(entry.id));
        }

        if char_count(&entry.title) > MAX_TITLE_CHARS {
            return Err(VaultDataError::EntryTitleTooLong(entry.id));
        }

        Ok(entry)
    }
}

impl VaultCategory {
    pub fn new(name: impl Into<String>, now_ms: i64) -> Result<Self, VaultDataError> {
        if now_ms < 0 {
            return Err(VaultDataError::InvalidCategoryTimestamp(Uuid::nil()));
        }

        let category = Self {
            id: Uuid::new_v4(),
            name: name.into(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };

        if category.name.trim().is_empty() {
            return Err(VaultDataError::EmptyCategoryName(category.id));
        }

        if char_count(&category.name) > MAX_CATEGORY_NAME_CHARS {
            return Err(VaultDataError::CategoryNameTooLong(category.id));
        }

        Ok(category)
    }
}

fn validate_site_icon(icon: &SiteIcon) -> Result<usize, VaultDataError> {
    if !valid_site_icon_hostname(&icon.hostname) {
        return Err(VaultDataError::InvalidSiteIconHostname);
    }

    if icon.png_base64.is_empty() {
        return Err(VaultDataError::EmptySiteIconData);
    }

    if icon.png_base64.len() > MAX_SITE_ICON_BASE64_CHARS {
        return Err(VaultDataError::SiteIconDataTooLarge);
    }

    let decoded = Zeroizing::new(
        BASE64_STANDARD
            .decode(icon.png_base64.as_bytes())
            .map_err(|_| VaultDataError::InvalidSiteIconBase64)?,
    );

    if decoded.len() > MAX_SITE_ICON_BYTES {
        return Err(VaultDataError::SiteIconDataTooLarge);
    }

    const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

    if !decoded.as_slice().starts_with(PNG_SIGNATURE) {
        return Err(VaultDataError::InvalidSiteIconPng);
    }

    if icon.updated_at_ms < 0 {
        return Err(VaultDataError::InvalidSiteIconTimestamp);
    }

    Ok(decoded.len())
}

fn valid_site_icon_hostname(hostname: &str) -> bool {
    if hostname.is_empty()
        || hostname != hostname.trim()
        || hostname.len() > MAX_SITE_ICON_HOSTNAME_CHARS
        || hostname.ends_with('.')
        || hostname != hostname.to_ascii_lowercase()
    {
        return false;
    }

    if hostname.parse::<IpAddr>().is_ok() {
        return true;
    }

    hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn validate_totp_config(entry_id: Uuid, config: &TotpConfig) -> Result<(), VaultDataError> {
    if config.secret_base64.is_empty() || config.secret_base64.len() > MAX_TOTP_SECRET_BASE64_CHARS
    {
        return Err(VaultDataError::InvalidTotpSecret(entry_id));
    }

    let decoded = Zeroizing::new(
        BASE64_STANDARD
            .decode(config.secret_base64.as_bytes())
            .map_err(|_| VaultDataError::InvalidTotpSecret(entry_id))?,
    );

    if decoded.len() < MIN_TOTP_SECRET_BYTES || decoded.len() > MAX_TOTP_SECRET_BYTES {
        return Err(VaultDataError::InvalidTotpSecret(entry_id));
    }

    if !matches!(config.digits, 6 | 8)
        || !(1..=MAX_TOTP_PERIOD_SECONDS).contains(&config.period_seconds)
    {
        return Err(VaultDataError::InvalidTotpSettings(entry_id));
    }

    Ok(())
}

fn validate_category(category: &VaultCategory) -> Result<(), VaultDataError> {
    if category.id.is_nil() {
        return Err(VaultDataError::NilCategoryId);
    }

    if category.name.trim().is_empty() {
        return Err(VaultDataError::EmptyCategoryName(category.id));
    }

    if char_count(&category.name) > MAX_CATEGORY_NAME_CHARS {
        return Err(VaultDataError::CategoryNameTooLong(category.id));
    }

    if !valid_timestamps(category.created_at_ms, category.updated_at_ms) {
        return Err(VaultDataError::InvalidCategoryTimestamp(category.id));
    }

    Ok(())
}

fn validate_entry(entry: &VaultEntry, category_ids: &HashSet<Uuid>) -> Result<(), VaultDataError> {
    if entry.id.is_nil() {
        return Err(VaultDataError::NilEntryId);
    }

    if entry.title.trim().is_empty() {
        return Err(VaultDataError::EmptyEntryTitle(entry.id));
    }

    if char_count(&entry.title) > MAX_TITLE_CHARS {
        return Err(VaultDataError::EntryTitleTooLong(entry.id));
    }

    if char_count(&entry.profile_name) > MAX_PROFILE_NAME_CHARS {
        return Err(VaultDataError::EntryProfileNameTooLong(entry.id));
    }

    if char_count(&entry.username) > MAX_USERNAME_CHARS {
        return Err(VaultDataError::EntryUsernameTooLong(entry.id));
    }

    if char_count(&entry.password) > MAX_PASSWORD_CHARS {
        return Err(VaultDataError::EntryPasswordTooLong(entry.id));
    }

    if let Some(totp) = entry.totp.as_ref() {
        validate_totp_config(entry.id, totp)?;
    }

    if char_count(&entry.url) > MAX_URL_CHARS {
        return Err(VaultDataError::EntryUrlTooLong(entry.id));
    }

    if char_count(&entry.notes) > MAX_NOTES_CHARS {
        return Err(VaultDataError::EntryNotesTooLong(entry.id));
    }

    if entry.tags.len() > MAX_TAGS_PER_ENTRY {
        return Err(VaultDataError::TooManyTags(entry.id));
    }

    let mut seen_tags = HashSet::with_capacity(entry.tags.len());

    for tag in &entry.tags {
        if tag.trim().is_empty() {
            return Err(VaultDataError::EmptyTag(entry.id));
        }

        if char_count(tag) > MAX_TAG_CHARS {
            return Err(VaultDataError::TagTooLong(entry.id));
        }

        if !seen_tags.insert(tag.as_str()) {
            return Err(VaultDataError::DuplicateTag(entry.id));
        }
    }

    if let Some(category_id) = entry.category_id {
        if !category_ids.contains(&category_id) {
            return Err(VaultDataError::UnknownCategory(entry.id));
        }
    }

    if !valid_timestamps(entry.created_at_ms, entry.updated_at_ms) {
        return Err(VaultDataError::InvalidEntryTimestamp(entry.id));
    }

    Ok(())
}

fn is_supported_schema(schema_version: u16) -> bool {
    (LEGACY_VAULT_DATA_SCHEMA_VERSION..=VAULT_DATA_SCHEMA_VERSION).contains(&schema_version)
}

fn valid_timestamps(created_at_ms: i64, updated_at_ms: i64) -> bool {
    created_at_ms >= 0 && updated_at_ms >= created_at_ms
}

fn char_count(value: &str) -> usize {
    value.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: i64 = 1_700_000_000_000;

    const MODEL_TEST_SECRET: &str = "MODEL_TEST_ONLY_SECRET";

    fn valid_sample_data() -> VaultData {
        let mut data = VaultData::new(NOW_MS).unwrap();

        let category = VaultCategory::new("Work", NOW_MS).unwrap();

        let category_id = category.id;

        let mut entry = VaultEntry::new("Example Account", NOW_MS).unwrap();

        entry.profile_name = "Personal".to_owned();
        entry.url = "https://example.test".to_owned();
        entry.username = "user@example.test".to_owned();
        entry.password = MODEL_TEST_SECRET.to_owned();
        entry.notes = "Test-only note".to_owned();
        entry.category_id = Some(category_id);
        entry.tags = vec!["work".to_owned(), "email".to_owned()];
        entry.favorite = true;

        data.categories.push(category);
        data.entries.push(entry);

        data.validate().unwrap();

        data
    }

    fn test_site_icon() -> SiteIcon {
        SiteIcon {
            hostname: "github.com".to_owned(),

            /*
             * PNG signature + ASCII "TEST".
             *
             * Full image decoding belongs to the hardened
             * fetch/normalization boundary. The data model
             * only accepts normalized PNG-shaped cache data.
             */
            png_base64: "iVBORw0KGgpURVNU".to_owned(),

            updated_at_ms: NOW_MS,
        }
    }

    #[test]
    fn new_vault_has_valid_defaults() {
        let data = VaultData::new(NOW_MS).unwrap();

        assert_eq!(data.schema_version, VAULT_DATA_SCHEMA_VERSION);
        assert!(!data.vault_id.is_nil());
        assert!(data.entries.is_empty());
        assert!(data.categories.is_empty());
        assert!(data.site_icons.is_empty());
        assert!(data.validate().is_ok());
    }

    fn json_with_schema(data: &VaultData, schema_version: u16) -> serde_json::Value {
        let mut value = serde_json::to_value(data).unwrap();

        value["schema_version"] = serde_json::json!(schema_version);

        value
    }

    #[test]
    fn current_schema_is_three_and_new_vaults_start_at_revision_zero() {
        assert_eq!(VAULT_DATA_SCHEMA_VERSION, 3);

        let data = VaultData::new(NOW_MS).unwrap();

        assert_eq!(data.schema_version, 3);
        assert_eq!(data.revision, 0);
    }

    #[test]
    fn upgrade_legacy_schema_upgrades_schema_one_and_two_without_touching_revision() {
        for legacy_version in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            let mut legacy = VaultData::new(NOW_MS).unwrap();
            legacy.schema_version = legacy_version;

            legacy.upgrade_legacy_schema();

            assert_eq!(legacy.schema_version, VAULT_DATA_SCHEMA_VERSION);
            assert_eq!(legacy.revision, 0);
        }

        let mut current = VaultData::new(NOW_MS).unwrap();
        current.revision = 41;

        current.upgrade_legacy_schema();

        assert_eq!(current.schema_version, VAULT_DATA_SCHEMA_VERSION);
        assert_eq!(current.revision, 41);
    }

    #[test]
    fn prepare_for_write_upgrades_legacy_schemas_to_revision_one() {
        for legacy_version in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            let mut data = valid_sample_data();
            data.schema_version = legacy_version;

            data.prepare_for_write().unwrap();

            assert_eq!(data.schema_version, VAULT_DATA_SCHEMA_VERSION);
            assert_eq!(data.revision, 1);
            assert_eq!(data.entries.len(), 1);
            assert_eq!(data.categories.len(), 1);
        }
    }

    #[test]
    fn prepare_for_write_increments_current_schema_by_exactly_one() {
        let mut data = valid_sample_data();

        for expected in 1..=3u64 {
            data.prepare_for_write().unwrap();

            assert_eq!(data.revision, expected);
            assert_eq!(data.schema_version, VAULT_DATA_SCHEMA_VERSION);
        }
    }

    #[test]
    fn prepare_for_write_rejects_overflow_without_wrapping_or_mutating() {
        let mut data = valid_sample_data();
        data.revision = u64::MAX;

        assert_eq!(
            data.prepare_for_write(),
            Err(VaultDataError::RevisionOverflow)
        );

        assert_eq!(data.revision, u64::MAX);
        assert_eq!(data.schema_version, VAULT_DATA_SCHEMA_VERSION);

        // One below the limit still works, and lands exactly on the limit.
        data.revision = u64::MAX - 1;

        data.prepare_for_write().unwrap();

        assert_eq!(data.revision, u64::MAX);
    }

    #[test]
    fn prepare_for_write_is_failure_atomic_when_validation_fails() {
        let mut data = valid_sample_data();
        data.schema_version = PRE_REVISION_VAULT_DATA_SCHEMA_VERSION;
        data.entries[0].title = String::new();

        assert!(matches!(
            data.prepare_for_write(),
            Err(VaultDataError::EmptyEntryTitle(_))
        ));

        assert_eq!(data.schema_version, PRE_REVISION_VAULT_DATA_SCHEMA_VERSION);
        assert_eq!(data.revision, 0);
    }

    #[test]
    fn prepare_for_write_rejects_unsupported_schemas_without_mutating() {
        for unsupported in [0, VAULT_DATA_SCHEMA_VERSION + 1, u16::MAX] {
            let mut data = valid_sample_data();
            data.schema_version = unsupported;
            data.revision = 5;

            assert_eq!(
                data.prepare_for_write(),
                Err(VaultDataError::UnsupportedSchemaVersion)
            );

            assert_eq!(data.schema_version, unsupported);
            assert_eq!(data.revision, 5);
        }
    }

    #[test]
    fn schema_three_serializes_revision_and_round_trips() {
        let mut data = valid_sample_data();
        data.revision = 12;

        let value = serde_json::to_value(&data).unwrap();

        assert_eq!(value["schema_version"], serde_json::json!(3));
        assert_eq!(value["revision"], serde_json::json!(12));

        let restored: VaultData = serde_json::from_value(value).unwrap();

        restored.validate().unwrap();

        assert_eq!(restored.revision, 12);
        assert!(restored == data);
    }

    #[test]
    fn legacy_schemas_never_serialize_a_revision() {
        for legacy_version in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            let mut data = valid_sample_data();
            data.schema_version = legacy_version;

            let value = serde_json::to_value(&data).unwrap();

            assert!(value.get("revision").is_none());
        }
    }

    #[test]
    fn legacy_payload_without_revision_reads_as_revision_zero() {
        for legacy_version in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            let mut value = json_with_schema(&valid_sample_data(), legacy_version);

            assert!(value.as_object_mut().unwrap().remove("revision").is_some());

            let restored: VaultData = serde_json::from_value(value).unwrap();

            restored.validate().unwrap();

            assert_eq!(restored.schema_version, legacy_version);
            assert_eq!(restored.revision, 0);
        }
    }

    #[test]
    fn schema_three_payload_missing_revision_is_rejected() {
        let mut value = serde_json::to_value(valid_sample_data()).unwrap();

        assert!(value.as_object_mut().unwrap().remove("revision").is_some());

        assert!(serde_json::from_value::<VaultData>(value).is_err());
    }

    #[test]
    fn malformed_revision_values_are_rejected_in_every_schema() {
        let malformed = [
            serde_json::json!(null),
            serde_json::json!("7"),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!(true),
            serde_json::json!([7]),
            // One past u64::MAX.
            serde_json::from_str::<serde_json::Value>("18446744073709551616").unwrap(),
        ];

        for schema_version in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
            VAULT_DATA_SCHEMA_VERSION,
        ] {
            for revision in &malformed {
                let mut value = json_with_schema(&valid_sample_data(), schema_version);

                value["revision"] = revision.clone();

                assert!(
                    serde_json::from_value::<VaultData>(value).is_err(),
                    "schema {schema_version} accepted revision {revision}"
                );
            }
        }
    }

    #[test]
    fn legacy_payload_carrying_a_revision_is_rejected() {
        for legacy_version in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            for revision in [0u64, 1, 9] {
                let mut value = json_with_schema(&valid_sample_data(), legacy_version);

                value["revision"] = serde_json::json!(revision);

                assert!(serde_json::from_value::<VaultData>(value).is_err());
            }
        }
    }

    #[test]
    fn schema_three_accepts_the_full_unsigned_range_of_revisions() {
        for revision in [0u64, 1, u64::from(u32::MAX) + 1, u64::MAX] {
            let mut value = serde_json::to_value(valid_sample_data()).unwrap();

            value["revision"] = serde_json::json!(revision);

            let restored: VaultData = serde_json::from_value(value).unwrap();

            restored.validate().unwrap();

            assert_eq!(restored.revision, revision);
        }
    }

    #[test]
    fn future_schema_is_rejected_by_validate_not_silently_downgraded() {
        let mut value = serde_json::to_value(valid_sample_data()).unwrap();

        value["schema_version"] = serde_json::json!(VAULT_DATA_SCHEMA_VERSION + 1);

        let parsed: VaultData = serde_json::from_value(value).unwrap();

        assert_eq!(parsed.schema_version, VAULT_DATA_SCHEMA_VERSION + 1);
        assert_eq!(
            parsed.validate(),
            Err(VaultDataError::UnsupportedSchemaVersion)
        );
    }

    #[test]
    fn in_memory_legacy_schema_with_nonzero_revision_is_invalid() {
        for legacy_version in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            let mut data = valid_sample_data();
            data.schema_version = legacy_version;
            data.revision = 1;

            assert_eq!(data.validate(), Err(VaultDataError::InvalidRevision));
        }
    }

    #[test]
    fn valid_entry_and_category_are_accepted() {
        let data = valid_sample_data();

        assert_eq!(data.entries.len(), 1);
        assert_eq!(data.categories.len(), 1);
        assert!(data.validate().is_ok());
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let mut data = valid_sample_data();

        data.schema_version = VAULT_DATA_SCHEMA_VERSION + 1;

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::UnsupportedSchemaVersion)
        ));
    }

    #[test]
    fn duplicate_entry_ids_are_rejected() {
        let mut data = valid_sample_data();

        let duplicate = data.entries[0].clone();
        data.entries.push(duplicate);

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::DuplicateEntryId(_))
        ));
    }

    #[test]
    fn duplicate_category_ids_are_rejected() {
        let mut data = valid_sample_data();

        let duplicate = data.categories[0].clone();
        data.categories.push(duplicate);

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::DuplicateCategoryId(_))
        ));
    }

    #[test]
    fn unknown_category_reference_is_rejected() {
        let mut data = valid_sample_data();

        data.entries[0].category_id = Some(Uuid::new_v4());

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::UnknownCategory(_))
        ));
    }

    #[test]
    fn empty_entry_title_is_rejected() {
        let result = VaultEntry::new("   ", NOW_MS);

        assert!(matches!(result, Err(VaultDataError::EmptyEntryTitle(_))));
    }

    #[test]
    fn oversized_password_is_rejected() {
        let mut data = valid_sample_data();

        data.entries[0].password = "x".repeat(MAX_PASSWORD_CHARS + 1);

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::EntryPasswordTooLong(_))
        ));
    }

    #[test]
    fn invalid_timestamp_order_is_rejected() {
        let mut data = valid_sample_data();

        data.entries[0].updated_at_ms = data.entries[0].created_at_ms - 1;

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::InvalidEntryTimestamp(_))
        ));
    }

    #[test]
    fn duplicate_tags_are_rejected() {
        let mut data = valid_sample_data();

        data.entries[0].tags = vec!["work".to_owned(), "work".to_owned()];

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::DuplicateTag(_))
        ));
    }

    #[test]
    fn serialization_round_trip_preserves_model() {
        let data = valid_sample_data();

        let json = serde_json::to_vec(&data).unwrap();

        let restored: VaultData = serde_json::from_slice(&json).unwrap();

        restored.validate().unwrap();

        assert!(restored == data);
    }

    #[test]
    fn sensitive_fields_are_zeroized_before_session_drop() {
        let mut data = valid_sample_data();

        assert!(!data.entries[0].password.is_empty());
        assert!(!data.entries[0].username.is_empty());
        assert!(!data.entries[0].url.is_empty());
        assert!(!data.entries[0].notes.is_empty());
        assert!(!data.categories[0].name.is_empty());

        data.zeroize_sensitive_fields();

        assert!(data.entries.is_empty());
        assert!(data.categories.is_empty());
    }

    #[test]
    fn individual_entry_sensitive_fields_can_be_zeroized() {
        let mut entry = VaultEntry::new("Sensitive title", NOW_MS).unwrap();

        entry.profile_name = "Sensitive profile".to_owned();
        entry.url = "https://sensitive.example".to_owned();
        entry.username = "sensitive-user".to_owned();
        entry.password = "sensitive-password".to_owned();
        entry.notes = "sensitive-notes".to_owned();
        entry.tags = vec!["private".to_owned(), "important".to_owned()];

        entry.zeroize_sensitive_fields();

        assert!(entry.title.is_empty());
        assert!(entry.profile_name.is_empty());
        assert!(entry.url.is_empty());
        assert!(entry.username.is_empty());
        assert!(entry.password.is_empty());
        assert!(entry.notes.is_empty());
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn legacy_entry_without_profile_name_deserializes_as_empty() {
        let data = valid_sample_data();

        let mut value = serde_json::to_value(&data).unwrap();

        let entry = value["entries"][0].as_object_mut().unwrap();

        assert!(entry.remove("profile_name").is_some());

        let restored: VaultData = serde_json::from_value(value).unwrap();

        assert_eq!(restored.schema_version, VAULT_DATA_SCHEMA_VERSION);

        assert!(restored.entries[0].profile_name.is_empty());

        restored.validate().unwrap();
    }

    #[test]
    fn oversized_profile_name_is_rejected() {
        let mut data = valid_sample_data();

        data.entries[0].profile_name = "x".repeat(MAX_PROFILE_NAME_CHARS + 1);

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::EntryProfileNameTooLong(_))
        ));
    }

    #[test]
    fn valid_cached_site_icon_is_accepted() {
        let mut data = valid_sample_data();

        data.site_icons.push(test_site_icon());

        assert!(data.validate().is_ok());
    }

    #[test]
    fn legacy_vault_without_site_icons_deserializes_as_empty() {
        let mut data = valid_sample_data();

        data.site_icons.push(test_site_icon());

        let mut value = serde_json::to_value(&data).unwrap();

        let object = value.as_object_mut().unwrap();

        assert!(object.remove("site_icons").is_some());

        let restored: VaultData = serde_json::from_value(value).unwrap();

        assert_eq!(restored.schema_version, VAULT_DATA_SCHEMA_VERSION);

        assert!(restored.site_icons.is_empty());
        restored.validate().unwrap();
    }

    #[test]
    fn duplicate_site_icon_hostname_is_rejected() {
        let mut data = valid_sample_data();

        let icon = test_site_icon();

        data.site_icons.push(icon.clone());
        data.site_icons.push(icon);

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::DuplicateSiteIconHostname)
        ));
    }

    #[test]
    fn non_png_site_icon_data_is_rejected() {
        let mut data = valid_sample_data();

        let mut icon = test_site_icon();

        icon.png_base64 = "VEVTVA==".to_owned();

        data.site_icons.push(icon);

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::InvalidSiteIconPng)
        ));
    }

    #[test]
    fn site_icon_metadata_can_be_zeroized() {
        let mut icon = test_site_icon();

        assert!(!icon.hostname.is_empty());
        assert!(!icon.png_base64.is_empty());

        icon.zeroize_sensitive_fields();

        assert!(icon.hostname.is_empty());
        assert!(icon.png_base64.is_empty());
    }

    #[test]
    fn current_schema_accepts_valid_totp_config() {
        let mut data = valid_sample_data();

        data.entries[0].totp = Some(TotpConfig {
            secret_base64: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=".to_owned(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
        });

        data.validate().unwrap();
    }

    #[test]
    fn legacy_schema_without_totp_remains_readable() {
        let mut data = valid_sample_data();

        data.schema_version = LEGACY_VAULT_DATA_SCHEMA_VERSION;
        data.entries[0].totp = None;

        data.validate().unwrap();
    }

    #[test]
    fn legacy_schema_cannot_carry_totp_secret() {
        let mut data = valid_sample_data();

        data.schema_version = LEGACY_VAULT_DATA_SCHEMA_VERSION;

        data.entries[0].totp = Some(TotpConfig {
            secret_base64: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=".to_owned(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
        });

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::LegacySchemaContainsTotp(_))
        ));
    }

    #[test]
    fn individual_totp_secret_can_be_zeroized() {
        let mut config = TotpConfig {
            secret_base64: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=".to_owned(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
        };

        config.zeroize_sensitive_fields();

        assert!(config.secret_base64.is_empty());
    }

    #[test]
    fn individual_category_name_can_be_zeroized() {
        let mut category = VaultCategory::new("Sensitive Category", NOW_MS).unwrap();

        assert!(!category.name.is_empty());

        category.zeroize_sensitive_fields();

        assert!(category.name.is_empty());
    }
}
