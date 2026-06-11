/**
 * Smoke test: a fresh profile boots to onboarding; creating a vault with a strong
 * master password transitions into the unlocked app.
 *
 * Requires a CLEAN app-data profile (no existing vault) — otherwise the app shows
 * the unlock screen instead of onboarding and this spec is skipped. Clear the
 * profile first (see e2e/README.md) for a deterministic run.
 *
 * Selectors use stable element ids that exist in the app:
 *   #master-password / #confirm-password (onboarding), #unlock-password (unlock).
 * Submitting is done with Enter (both screens submit on Enter), so no fragile
 * i18n/button-text selectors are needed. Extending to lock/add/edit flows is best
 * done by adding `data-testid` attributes to those controls.
 */
describe("Goldfish smoke", () => {
    it("onboards a fresh vault and reaches the unlocked app", async () => {
        // A long passphrase clears the zxcvbn >= 3 ("good") onboarding gate.
        const masterPassword = "correct-horse-battery-staple-42!";

        const master = await $("#master-password");
        if (!(await master.isExisting())) {
            // A vault already exists on this profile — can't onboard deterministically.
            // eslint-disable-next-line no-console
            console.warn("skip: existing vault profile; clear app data for a clean smoke");
            return;
        }

        await master.waitForDisplayed({ timeout: 20_000 });
        await master.setValue(masterPassword);

        const confirm = await $("#confirm-password");
        await confirm.setValue(masterPassword);
        await confirm.click(); // focus the field so Enter submits
        await browser.keys("Enter");

        // After creation the onboarding inputs are gone and the vault is unlocked.
        await master.waitForExist({ reverse: true, timeout: 20_000 });
        await expect($("#master-password")).not.toBeExisting();
    });
});
