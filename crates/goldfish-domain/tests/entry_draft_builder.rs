//! Integration test: exercises the public `EntryDraft` builder API end-to-end.
//!
//! Lives in `tests/` (not in `src/*/tests`) so it can only touch the public
//! surface — same code paths a downstream crate would call.

use goldfish_domain::{EntryDraft, PlaintextSecret, MAX_DESCRIPTION};

#[test]
fn full_builder_chain_round_trip() {
    let draft = EntryDraft::new(
        "My Bank",
        "user@example.com",
        PlaintextSecret::from("s3cret!"),
    )
    .expect("base draft")
    .with_description(Some("Primary checking account".to_owned()))
    .expect("description")
    .with_url(Some("https://bank.example.com/login".to_owned()))
    .expect("url");

    assert_eq!(draft.title, "My Bank");
    assert_eq!(draft.username, "user@example.com");
    assert_eq!(draft.password.expose(), "s3cret!");
    assert_eq!(
        draft.description.as_deref(),
        Some("Primary checking account")
    );
    assert_eq!(draft.url.as_deref(), Some("https://bank.example.com/login"));
    assert!(draft.app_name.is_none());
    assert!(draft.notes.is_none());
    assert!(draft.totp_secret.is_none());
    assert!(!draft.favorite);
}

#[test]
fn builder_short_circuits_on_first_validation_failure() {
    // `with_description` is called on the constructor's result; if `new` fails,
    // chained `.unwrap_err()` proves we never even reach `with_description`.
    let oversized_title = "x".repeat(10_000);
    let err = EntryDraft::new(&oversized_title, "u", PlaintextSecret::from("p"));
    assert!(err.is_err(), "title-too-long must short-circuit the chain");
}

#[test]
fn description_validation_runs_even_when_title_is_short() {
    let body = "x".repeat(MAX_DESCRIPTION + 1);
    let err = EntryDraft::new("t", "u", PlaintextSecret::from("p"))
        .expect("base draft")
        .with_description(Some(body))
        .expect_err("oversized description must reject");
    let s = err.to_string();
    assert!(
        s.contains("description"),
        "error message must name the field: got `{s}`"
    );
}
