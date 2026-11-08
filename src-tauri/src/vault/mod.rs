pub mod backup;
pub(crate) mod file_identity;
pub(crate) mod handle_ops;
pub(crate) mod held_removal;
#[cfg(all(test, windows))]
mod legacy_layout_assessment;
#[cfg(all(test, windows))]
mod legacy_record_exchange;
pub mod lifecycle;
pub(crate) mod new_copy_file;
pub mod session;
pub mod storage;
pub mod sync_file_adapter;
pub mod sync_state_store;
mod target_exchange;
