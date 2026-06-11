//! Use-case catalogue.
//!
//! Each use case is a method on [`crate::VaultService`]:
//!
//! | Use case          | Method                              | Phase |
//! |-------------------|-------------------------------------|-------|
//! | Create vault      | [`VaultService::create_vault`]      | 2     |
//! | Unlock vault      | [`VaultService::unlock_vault`]      | 2     |
//! | Vault exists?     | [`VaultService::vault_exists`]      | 2     |
//! | Add entry         | [`VaultService::add_entry`]         | 2     |
//! | Get entry         | [`VaultService::get_entry`]         | 2     |
//! | List entries      | [`VaultService::list_entries`]      | 2     |
//! | Update entry      | [`VaultService::update_entry`]      | 2     |
//! | Delete entry      | [`VaultService::delete_entry`]      | 2     |
//! | Import entries    | [`VaultService::import_entries`]    | 11    |
//! | Export vault      | [`VaultService::export_vault`]      | 12    |
//! | Import `.goldfish`| [`VaultService::import_vault_file`] | 12    |
//!
//! Cross-cutting use cases also live on the service / free functions: generate
//! password (6), estimate strength (6), TOTP (8), check HIBP (10).
//!
//! [`VaultService`]: crate::VaultService
//! [`VaultService::create_vault`]: crate::VaultService::create_vault
//! [`VaultService::unlock_vault`]: crate::VaultService::unlock_vault
//! [`VaultService::vault_exists`]: crate::VaultService::vault_exists
//! [`VaultService::add_entry`]: crate::VaultService::add_entry
//! [`VaultService::get_entry`]: crate::VaultService::get_entry
//! [`VaultService::list_entries`]: crate::VaultService::list_entries
//! [`VaultService::update_entry`]: crate::VaultService::update_entry
//! [`VaultService::delete_entry`]: crate::VaultService::delete_entry
//! [`VaultService::import_entries`]: crate::VaultService::import_entries
//! [`VaultService::export_vault`]: crate::VaultService::export_vault
//! [`VaultService::import_vault_file`]: crate::VaultService::import_vault_file
