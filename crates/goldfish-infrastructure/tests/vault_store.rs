//! Cross-crate integration test: the real `VaultService` wired to the real
//! SQLCipher store + sidecar metadata repo, on a tempfile vault. Exercises the
//! full Phase 0–3 stack end to end, including encryption at rest.

use std::sync::Arc;

use goldfish_application::VaultService;
use goldfish_domain::{EntryDraft, KdfParams, PlaintextSecret};
use goldfish_infrastructure::{
    FileVaultMetadataRepository, KeyringStore, SqliteEntryStore, SystemClock,
};
use tempfile::tempdir;

/// Low-cost KDF so the suite stays fast (real vaults use `KdfParams::DEFAULT`).
const fn fast() -> KdfParams {
    KdfParams {
        memory_kib: 256,
        iterations: 1,
        parallelism: 1,
    }
}

fn wire(dir: &std::path::Path) -> (VaultService, std::path::PathBuf) {
    let db_path = dir.join("vault.db");
    let meta_path = dir.join("vault.meta.json");
    let store = Arc::new(SqliteEntryStore::new(db_path.clone()));
    let meta = Arc::new(FileVaultMetadataRepository::new(meta_path));
    let svc = VaultService::new(
        store.clone(),
        store,
        meta,
        Arc::new(SystemClock),
        Arc::new(KeyringStore::new()),
    );
    (svc, db_path)
}

fn draft(title: &str, user: &str, pass: &str) -> EntryDraft {
    EntryDraft::new(title, user, PlaintextSecret::from(pass)).unwrap()
}

#[tokio::test]
async fn full_lifecycle_persists_across_lock_and_unlock() {
    let dir = tempdir().unwrap();
    let (svc, _db) = wire(dir.path());

    // Create + add while unlocked.
    let session = svc.create_vault("master-pw", fast()).await.unwrap();
    let created = svc
        .add_entry(&session, draft("GitHub", "octocat", "hunter2"))
        .await
        .unwrap();

    // Lock: drop the session and close the encrypted store.
    drop(session);
    svc.lock().await.unwrap();

    // A second, freshly wired service over the SAME files must unlock and read.
    let (svc2, _) = wire(dir.path());
    assert!(svc2.vault_exists().await.unwrap());
    let session2 = svc2.unlock_vault("master-pw").await.unwrap();
    let loaded = svc2.get_entry(&session2, created.id).await.unwrap();

    assert_eq!(loaded.title, "GitHub");
    assert_eq!(loaded.username, "octocat");
    assert_eq!(loaded.password.expose(), "hunter2");
}

#[tokio::test]
async fn crud_and_list_round_trip() {
    let dir = tempdir().unwrap();
    let (svc, _db) = wire(dir.path());
    let session = svc.create_vault("pw", fast()).await.unwrap();

    svc.add_entry(&session, draft("Zeta", "u", "p"))
        .await
        .unwrap();
    let mid = svc
        .add_entry(&session, draft("Mid", "u", "p"))
        .await
        .unwrap();
    svc.add_entry(&session, draft("Alpha", "u", "p"))
        .await
        .unwrap();

    // New entries append to the end, so the default order is insertion order.
    let list = svc.list_entries(None).await.unwrap();
    let titles: Vec<_> = list.iter().map(|s| s.title.as_str()).collect();
    assert_eq!(titles, ["Zeta", "Mid", "Alpha"]);

    // Update bumps version and persists.
    let mut entry = svc.get_entry(&session, mid.id).await.unwrap();
    entry.password = PlaintextSecret::from("rotated");
    let updated = svc.update_entry(&session, entry).await.unwrap();
    assert_eq!(updated.version, 2);
    let reloaded = svc.get_entry(&session, mid.id).await.unwrap();
    assert_eq!(reloaded.password.expose(), "rotated");

    // Delete.
    svc.delete_entry(mid.id).await.unwrap();
    assert_eq!(svc.list_entries(None).await.unwrap().len(), 2);
}

#[tokio::test]
async fn ordering_and_folder_moves_persist_on_real_store() {
    // Exercises the new SQL paths against real SQLCipher: append-on-insert,
    // per-view reorder, folder moves, and the folder-change branch in UPDATE.
    let dir = tempdir().unwrap();
    let (svc, _db) = wire(dir.path());
    let session = svc.create_vault("pw", fast()).await.unwrap();
    let work = svc.create_folder("Work").await.unwrap();

    let mut a = draft("A", "u", "p");
    a.folder_id = Some(work.id);
    let a = svc.add_entry(&session, a).await.unwrap();
    let mut b = draft("B", "u", "p");
    b.folder_id = Some(work.id);
    let b = svc.add_entry(&session, b).await.unwrap();
    let c = svc.add_entry(&session, draft("C", "u", "p")).await.unwrap(); // unfiled

    let titles = |list: Vec<goldfish_domain::EntrySummary>| {
        list.into_iter().map(|e| e.title).collect::<Vec<_>>()
    };

    // All-entries view defaults to insertion order; the folder view is its own.
    assert_eq!(
        titles(svc.list_entries(None).await.unwrap()),
        ["A", "B", "C"]
    );
    assert_eq!(
        titles(svc.list_entries(Some(work.id)).await.unwrap()),
        ["A", "B"]
    );

    // Reorder the All view only; the folder order is untouched.
    svc.reorder_entries(None, &[c.id, b.id, a.id])
        .await
        .unwrap();
    assert_eq!(
        titles(svc.list_entries(None).await.unwrap()),
        ["C", "B", "A"]
    );
    assert_eq!(
        titles(svc.list_entries(Some(work.id)).await.unwrap()),
        ["A", "B"]
    );

    // Move C into the folder: it appends to the folder, All order unchanged.
    svc.move_entry_to_folder(c.id, Some(work.id)).await.unwrap();
    assert_eq!(
        titles(svc.list_entries(Some(work.id)).await.unwrap()),
        ["A", "B", "C"]
    );
    assert_eq!(
        titles(svc.list_entries(None).await.unwrap()),
        ["C", "B", "A"]
    );

    // Persists across lock/unlock (positions live in the encrypted DB).
    drop(session);
    svc.lock().await.unwrap();
    let (svc2, _) = wire(dir.path());
    svc2.unlock_vault("pw").await.unwrap();
    assert_eq!(
        titles(svc2.list_entries(None).await.unwrap()),
        ["C", "B", "A"]
    );
    assert_eq!(
        titles(svc2.list_entries(Some(work.id)).await.unwrap()),
        ["A", "B", "C"]
    );
}

#[tokio::test]
async fn folder_appearance_persists_on_real_store() {
    let dir = tempdir().unwrap();
    let (svc, _db) = wire(dir.path());
    let session = svc.create_vault("pw", fast()).await.unwrap();
    let folder = svc.create_folder("Work").await.unwrap();
    assert_eq!(folder.appearance, goldfish_domain::Appearance::default());

    svc.set_folder_appearance(
        folder.id,
        goldfish_domain::Appearance {
            background: Some("#0A0B0C".to_owned()),
            text_color: Some("#FFFFFF".to_owned()),
            bold: true,
            italic: true,
            font_size: Some(18),
        },
    )
    .await
    .unwrap();

    // Survives a lock/unlock cycle (lives in the encrypted DB).
    drop(session);
    svc.lock().await.unwrap();
    let (svc2, _) = wire(dir.path());
    svc2.unlock_vault("pw").await.unwrap();
    let loaded = svc2.list_folders().await.unwrap();
    let a = &loaded[0].appearance;
    assert_eq!(a.background.as_deref(), Some("#0a0b0c")); // normalized lowercase
    assert_eq!(a.text_color.as_deref(), Some("#ffffff"));
    assert!(a.bold && a.italic);
    assert_eq!(a.font_size, Some(18));
}

#[tokio::test]
async fn tags_assign_persist_and_cascade_on_real_store() {
    let dir = tempdir().unwrap();
    let (svc, _db) = wire(dir.path());
    let session = svc.create_vault("pw", fast()).await.unwrap();

    let work = svc.create_tag("work").await.unwrap();
    let urgent = svc.create_tag("urgent").await.unwrap();

    let mut d = draft("Server", "root", "p");
    d.tags = vec![work.id, urgent.id];
    let entry = svc.add_entry(&session, d).await.unwrap();

    // Tags survive a lock/unlock cycle and appear on both summary and detail.
    drop(session);
    svc.lock().await.unwrap();
    let (svc2, _) = wire(dir.path());
    let session2 = svc2.unlock_vault("pw").await.unwrap();

    let summary = &svc2.list_entries(None).await.unwrap()[0];
    assert_eq!(summary.tags.len(), 2);
    let loaded = svc2.get_entry(&session2, entry.id).await.unwrap();
    assert!(loaded.tags.contains(&work.id) && loaded.tags.contains(&urgent.id));

    // Deleting a tag removes it from the entry (FK cascade) but keeps the entry.
    svc2.delete_tag(work.id).await.unwrap();
    assert_eq!(svc2.list_tags().await.unwrap().len(), 1);
    let after = svc2.get_entry(&session2, entry.id).await.unwrap();
    assert_eq!(after.tags, vec![urgent.id]);
}

#[tokio::test]
async fn attachments_seal_persist_and_cascade_on_real_store() {
    let dir = tempdir().unwrap();
    let (svc, _db) = wire(dir.path());
    let session = svc.create_vault("pw", fast()).await.unwrap();
    let entry = svc
        .add_entry(&session, draft("Server", "root", "p"))
        .await
        .unwrap();

    let contents = b"-----BEGIN KEY-----\x00\x01\xfe\xff binary \n payload-----END-----";
    let meta = svc
        .add_attachment(&session, entry.id, "id_ed25519", contents)
        .await
        .unwrap();
    assert_eq!(meta.size, contents.len() as u64);

    // Survives lock/unlock and decrypts to the exact bytes.
    drop(session);
    svc.lock().await.unwrap();
    let (svc2, _) = wire(dir.path());
    let session2 = svc2.unlock_vault("pw").await.unwrap();

    let list = svc2.list_attachments(entry.id).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "id_ed25519");
    let (name, bytes) = svc2.open_attachment(&session2, meta.id).await.unwrap();
    assert_eq!(name, "id_ed25519");
    assert_eq!(bytes.as_slice(), contents);

    // Deleting the entry cascades its attachments (FK ON DELETE CASCADE).
    svc2.delete_entry(entry.id).await.unwrap();
    assert!(svc2.list_attachments(entry.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn wrong_password_cannot_unlock() {
    let dir = tempdir().unwrap();
    let (svc, _db) = wire(dir.path());
    svc.create_vault("right-pw", fast()).await.unwrap();
    svc.lock().await.unwrap();

    let (svc2, _) = wire(dir.path());
    let err = svc2.unlock_vault("WRONG-pw").await;
    assert!(err.is_err(), "wrong password must not unlock");
}

#[tokio::test]
async fn database_file_is_encrypted_at_rest() {
    let dir = tempdir().unwrap();
    let (svc, db_path) = wire(dir.path());

    let session = svc.create_vault("master-pw", fast()).await.unwrap();
    svc.add_entry(
        &session,
        draft(
            "UNIQUE_TITLE_MARKER_42",
            "UNIQUE_USER_MARKER",
            "UNIQUE_SECRET_MARKER",
        ),
    )
    .await
    .unwrap();

    // Flush + close so all pages are written to the file.
    drop(session);
    svc.lock().await.unwrap();

    let bytes = std::fs::read(&db_path).unwrap();

    // SQLCipher encrypts the header too — a plaintext SQLite DB would start with
    // "SQLite format 3\0".
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "file must not be a plaintext SQLite database"
    );

    // None of our markers (plaintext title OR encrypted secret) may appear in
    // the raw file — the whole page is SQLCipher-encrypted.
    for marker in [
        b"UNIQUE_TITLE_MARKER_42".as_slice(),
        b"UNIQUE_USER_MARKER".as_slice(),
        b"UNIQUE_SECRET_MARKER".as_slice(),
    ] {
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker),
            "marker leaked into the on-disk file: {}",
            String::from_utf8_lossy(marker)
        );
    }
}
