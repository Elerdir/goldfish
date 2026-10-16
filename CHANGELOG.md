# Changelog

Všechny významné změny Goldfishe. Text sekcí jde jako „Co je nového" do UpdateHubu,
k aktualizaci v aplikaci a na www.niderle.cz — piš ho pro uživatele, ne pro vývojáře.

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/1.1.0/), verzování
drží [SemVer](https://semver.org/lang/cs/). Verzi určuje tag vydání z Dispatche; před
vydáním zapiš změny pod `[Unreleased]`.

---

## [Unreleased]

### Opraveno
- Položka „Všechny záznamy“ v levém panelu se už neroztahuje přes celou výšku okna.

## [1.1.0] - 2026-10-16

### Přidáno
- Automatické aktualizace: Goldfish po spuštění sám zjistí novou verzi a nabídne ji
  v Nastavení → Aktualizace (stažení, instalace a restart jedním klikem). Aktualizace
  jsou podepsané a aplikace ověřuje podpis před instalací.

### Změněno
- Aktualizované knihovny včetně bezpečnostních oprav (TLS pro kontrolu uniklých hesel,
  zpracování XML) a novější verze Tauri.

## [1.0.0] - 2026-06-20

### Přidáno
- První vydání: šifrovaný trezor hesel (Argon2id + XChaCha20-Poly1305 + SQLCipher),
  generátor hesel, TOTP, složky a štítky, přílohy, import z Bitwardenu, KeePassXC
  a 1Passwordu, zálohy, kontrola uniklých hesel, odemykání biometrikou.
