//! OS credential-store adapter for the `OsKeyStore` port.
//!
//! Stores secrets in the platform credential store via the `keyring` crate
//! (Windows Credential Manager / macOS Keychain / Linux Secret Service).
//!
//! Retrieval is gated by an OS biometric consent prompt:
//! - **Windows** — Windows Hello (`UserConsentVerifier`).
//! - **macOS** — Touch ID (LocalAuthentication `LAContext`).
//!
//! turning "stored on this device" into "released only after biometric/PIN
//! verification". On platforms without an implemented gate (e.g. Linux) the gate
//! is unavailable, so [`OsKeyStore::biometrics_available`] reports `false`.
//!
//! Security note: the stored key sits in DPAPI/Keychain (user-session protected)
//! and the prompt is a consent gate — this is convenience biometrics, not a
//! hardware-bound second factor. The master password remains the root secret, and
//! the per-device biometric wrap never travels with the encrypted export (which is
//! password-only), so backups stay portable across machines and operating systems.

use async_trait::async_trait;
use goldfish_application::{ApplicationError, OsKeyStore};
use keyring::Entry;

/// Service name under which credentials are grouped in the OS store. Matches the
/// app's bundle identifier so OS keychains group Goldfish secrets coherently.
const SERVICE: &str = "com.goldfish.desktop";

/// `OsKeyStore` backed by the platform credential store + Windows Hello.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyringStore;

impl KeyringStore {
    /// Creates a new keyring-backed keystore.
    pub const fn new() -> Self {
        Self
    }
}

// Taken by value so they compose directly with `.map_err(map_keyring)`, which
// hands the closure an owned error.
#[allow(clippy::needless_pass_by_value)]
fn map_keyring(e: keyring::Error) -> ApplicationError {
    ApplicationError::Storage(format!("keyring: {e}"))
}

#[allow(clippy::needless_pass_by_value)]
fn join_err(e: tokio::task::JoinError) -> ApplicationError {
    ApplicationError::Storage(e.to_string())
}

#[async_trait]
impl OsKeyStore for KeyringStore {
    fn biometrics_available(&self) -> bool {
        platform::biometrics_available()
    }

    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), ApplicationError> {
        let label = label.to_owned();
        let secret = secret.to_vec();
        tokio::task::spawn_blocking(move || {
            Entry::new(SERVICE, &label)
                .map_err(map_keyring)?
                .set_secret(&secret)
                .map_err(map_keyring)
        })
        .await
        .map_err(join_err)?
    }

    async fn retrieve(&self, label: &str) -> Result<Vec<u8>, ApplicationError> {
        let label = label.to_owned();
        tokio::task::spawn_blocking(move || {
            platform::require_consent("Unlock Goldfish")?;
            Entry::new(SERVICE, &label)
                .map_err(map_keyring)?
                .get_secret()
                .map_err(map_keyring)
        })
        .await
        .map_err(join_err)?
    }

    async fn delete(&self, label: &str) -> Result<(), ApplicationError> {
        let label = label.to_owned();
        tokio::task::spawn_blocking(move || {
            Entry::new(SERVICE, &label)
                .map_err(map_keyring)?
                .delete_credential()
                .map_err(map_keyring)
        })
        .await
        .map_err(join_err)?
    }
}

#[cfg(windows)]
mod platform {
    // OS integration needs Win32 FFI (COM init + the consent-verifier interop).
    // Each `unsafe` block is documented with a `// SAFETY:` note; the crate
    // otherwise denies unsafe.
    #![allow(unsafe_code)]

    use goldfish_application::ApplicationError;
    use windows::core::{factory, HSTRING};
    use windows::Foundation::IAsyncOperation;
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

    /// Initializes COM (multithreaded) for the current thread so WinRT runtime
    /// classes can be activated.
    ///
    /// Tauri command handlers run on tokio worker threads where COM has not been
    /// initialized. Without this, activating `UserConsentVerifier` fails with
    /// `CO_E_NOTINITIALIZED` and the availability check silently reports `false`
    /// — which is exactly why the biometric toggle never appeared. Idempotent:
    /// re-initializing a thread (`S_FALSE`) or one already in another mode
    /// (`RPC_E_CHANGED_MODE`) is harmless and still leaves COM usable, so we
    /// ignore the result. These worker threads live for the app's lifetime, so we
    /// intentionally never call `CoUninitialize`.
    fn ensure_com() {
        // SAFETY: `CoInitializeEx` is safe to call with a null reserved pointer
        // (`None`); every possible HRESULT outcome leaves COM usable on this
        // thread, so the result is intentionally discarded.
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }
    }

    pub fn biometrics_available() -> bool {
        ensure_com();
        match UserConsentVerifier::CheckAvailabilityAsync().and_then(|op| op.get()) {
            Ok(UserConsentVerifierAvailability::Available) => {
                tracing::info!("biometrics: Windows Hello available");
                true
            }
            Ok(other) => {
                // DeviceNotPresent / NotConfiguredForUser / DisabledByPolicy / …
                tracing::warn!(reason = ?other, "biometrics: Windows Hello unavailable");
                false
            }
            Err(e) => {
                tracing::warn!(error = %e, "biometrics: availability check failed");
                false
            }
        }
    }

    pub fn require_consent(message: &str) -> Result<(), ApplicationError> {
        ensure_com();
        let result = request_verification(message)
            .map_err(|e| ApplicationError::BiometricFailed(e.to_string()))?;
        if result == UserConsentVerificationResult::Verified {
            tracing::info!("biometrics: consent verified");
            Ok(())
        } else {
            tracing::warn!(result = ?result, "biometrics: consent not granted");
            Err(ApplicationError::BiometricFailed(format!("{result:?}")))
        }
    }

    /// Requests Hello verification, parenting the prompt to the foreground window
    /// (the Goldfish window — consent is always user-initiated from it). Win32
    /// apps must use the interop variant; the windowless `RequestVerificationAsync`
    /// is unreliable outside a packaged/UWP context. Falls back to the windowless
    /// call if the interop path is unavailable.
    fn request_verification(message: &str) -> windows::core::Result<UserConsentVerificationResult> {
        let msg = HSTRING::from(message);
        match request_for_window(&msg) {
            Ok(result) => Ok(result),
            Err(e) => {
                tracing::warn!(error = %e, "biometrics: windowed prompt failed, trying windowless");
                UserConsentVerifier::RequestVerificationAsync(&msg)?.get()
            }
        }
    }

    fn request_for_window(msg: &HSTRING) -> windows::core::Result<UserConsentVerificationResult> {
        // SAFETY: `GetForegroundWindow` is always safe to call; it may return a
        // null `HWND`, which the interop call tolerates (system-owned prompt).
        let hwnd: HWND = unsafe { GetForegroundWindow() };
        let interop: IUserConsentVerifierInterop = factory::<UserConsentVerifier, _>()?;
        // SAFETY: `interop` is a valid activation-factory interface, and `hwnd` /
        // `msg` outlive the synchronous `.get()` wait below.
        let op: IAsyncOperation<UserConsentVerificationResult> =
            unsafe { interop.RequestVerificationForWindowAsync(hwnd, msg)? };
        op.get()
    }
}

#[cfg(target_os = "macos")]
mod platform {
    // macOS Touch ID gate via the LocalAuthentication framework. Availability is a
    // no-prompt preflight (`canEvaluatePolicy:`); consent shows the system Touch ID
    // sheet (`evaluatePolicy:localizedReason:reply:`), whose async reply block we
    // bridge to a blocking call over a channel. We run inside `spawn_blocking` and
    // the reply fires on a framework-private queue, so blocking the calling thread
    // cannot deadlock. Each `unsafe` block is `// SAFETY:`-documented.
    #![allow(unsafe_code)]

    use std::sync::mpsc;

    use block2::RcBlock;
    use goldfish_application::ApplicationError;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    /// Touch ID only (no device-password fallback): the toggle and prompt are
    /// genuinely biometric. Without (or with broken) Touch ID the user falls back
    /// to the master password in Goldfish itself.
    const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

    fn new_context() -> Retained<LAContext> {
        // SAFETY: `LAContext::new` allocates and initializes a fresh context.
        unsafe { LAContext::new() }
    }

    pub fn biometrics_available() -> bool {
        let context = new_context();
        // SAFETY: a pure preflight query — shows no UI and has no preconditions.
        match unsafe { context.canEvaluatePolicy_error(POLICY) } {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(reason = %e.localizedDescription(), "biometrics: Touch ID unavailable");
                false
            }
        }
    }

    pub fn require_consent(message: &str) -> Result<(), ApplicationError> {
        let context = new_context();
        let reason = NSString::from_str(message);
        let (tx, rx) = mpsc::channel::<Result<(), String>>();

        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            if success.as_bool() {
                let _ = tx.send(Ok(()));
            } else {
                // SAFETY: on failure the framework passes a valid NSError or null;
                // `as_ref` yields `None` for null.
                let msg = unsafe { error.as_ref() }.map_or_else(
                    || "biometric verification failed".to_owned(),
                    |e| e.localizedDescription().to_string(),
                );
                let _ = tx.send(Err(msg));
            }
        });

        // SAFETY: `reason`, `reply` and `context` are all kept alive across the
        // blocking `recv()` below (so the in-progress evaluation isn't cancelled);
        // the reply block only sends across a channel.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(POLICY, &reason, &reply);
        }

        match rx.recv() {
            Ok(Ok(())) => {
                tracing::info!("biometrics: Touch ID verified");
                Ok(())
            }
            Ok(Err(msg)) => {
                tracing::warn!(error = %msg, "biometrics: Touch ID denied or failed");
                Err(ApplicationError::BiometricFailed(msg))
            }
            Err(_) => Err(ApplicationError::BiometricFailed(
                "biometric reply was dropped".to_owned(),
            )),
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use goldfish_application::ApplicationError;

    // Biometric gating is not yet implemented on this platform (e.g. Linux);
    // storage still works via the keyring, but we don't advertise biometric
    // support.
    pub const fn biometrics_available() -> bool {
        false
    }

    pub const fn require_consent(_message: &str) -> Result<(), ApplicationError> {
        Err(ApplicationError::BiometricUnavailable)
    }
}
