# Arx Notes `:crypto`

[![crypto CI](https://github.com/ArxSecretorum/arxnotes-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/ArxSecretorum/arxnotes-crypto/actions/workflows/ci.yml)

> 🇷🇺 [Русская версия](README.ru.md)

Open cryptographic core of the Arx Notes app — a self-contained Android library with **no
dependencies on the app's UI or data**. It can be read, audited and reused on its own.

**Don't trust — verify.** Security here rests on keys and passwords, never on code secrecy
(Kerckhoffs's principle). Everything below is checkable: read the sources, run the tests,
reproduce the reference vectors.

License: **Apache-2.0** (see [LICENSE](LICENSE)).
Security policy & threat model → [SECURITY.md](SECURITY.md) · External-audit map →
[AUDIT-SCOPE.md](AUDIT-SCOPE.md) · Test coverage → [TESTING.md](TESTING.md).

## ⚠️ Audit status (honest)

This module is covered by its **own automated test suite** (73 tests, including RFC 5869 and
RFC 9106 known-answer vectors) and an **internal self-assessment**. It has **NOT** undergone an
independent external security audit. Nothing in this repository should be read as third-party
validation. **Independent review is welcome** — [AUDIT-SCOPE.md](AUDIT-SCOPE.md) is a ready map.

## What's inside

| Component | Role | Primitives |
|---|---|---|
| `MasterKeyManager` | Root of trust: a random 256-bit master secret wrapped by an Android Keystore key; derives purpose-specific subkeys. | AES-256-GCM (Keystore), HKDF-SHA256 |
| `Hkdf` *(internal)* | Domain-separated key derivation from the master (RFC 5869). | HMAC-SHA256 |
| `AeadBlob` *(internal)* | Self-describing AES-GCM blob `[ver][IV][ct+tag]`. | AES-256-GCM |
| `AudioCrypto` | Encrypts voice-note bytes. | AES-256-GCM, key = HKDF(`audio`) |
| `BackupCrypto` | Password-based backup files. | Argon2id + AES-256-GCM |
| `PinHasher` | One-way hash of the lock PIN (verification, not decryption). | Argon2id (salt + hash) |

Public API: `MasterKeyManager`, `AudioCrypto`, `BackupCrypto`, `PinHasher`,
`DeviceLockedException`, `KeyInvalidatedException`. `AeadBlob` and `Hkdf` are `internal`.

## Key hierarchy

```
Android Keystore (non-exportable; hardware/TEE where the platform provides it)
        │  AES-GCM wrap
        ▼
   Master secret (32 random bytes; on disk only as an encrypted blob)
        │  HKDF-SHA256(info=…)
        ├── info "app.safenote/db/v1"     → SQLCipher key (used in the app module)
        └── info "app.safenote/audio/v1"  → AudioCrypto key

User password ──Argon2id(salt, params)──► backup-file key   (unrelated to the master)
Lock PIN     ──Argon2id(salt)──► verification hash           (one-way, not a key)
```

One secret is never reused directly across two cryptosystems: working keys are independent
HKDF subkeys with distinct domain labels.

> **Note — the `app.safenote/*` labels are frozen (not a branding leftover).** The `app.safenote/…`
> prefix in the HKDF domain labels (and the `safenote_master_key` Keystore alias) is a
> **backward-compatibility identifier, not a branding string** — it is intentionally *not* renamed
> to `arxnotes`. Changing these values would derive different keys / orphan the wrap key and make
> existing encrypted data unreadable; they may change only via a versioned migration (e.g. `/v2`).

## Parameters

- **Symmetric:** AES-256-GCM, 96-bit nonce, 128-bit tag. Authenticated encryption only — no unauthenticated mode anywhere.
- **Master secret:** 256-bit, `SecureRandom`; stored on disk only as a Keystore-wrapped blob. The Keystore wrap key uses `setUnlockedDeviceRequired(true)` on API ≥ 28.
- **Subkey KDF:** HKDF-SHA256, domain labels `app.safenote/db/v1`, `app.safenote/audio/v1`.
- **Backup KDF:** Argon2id, m = 64 MiB, t = 3, p = 1. Header parameters are clamped (≤ 128 MiB / ≤ 10 / ≤ 4) **before** Argon2 runs, to bound DoS.
- **PIN hash:** Argon2id, m = 32 MiB, t = 2, p = 1, 16-byte salt; constant-time compare (`MessageDigest.isEqual`).
- **DB encryption:** SQLCipher, keyed by the HKDF `db` subkey — wired in the **app** module, not here (see [SECURITY.md](SECURITY.md)).

## File formats

```
AeadBlob:  version(1) | IV(12) | ciphertext+tag(16)
Backup:    magic "SNBK"(4) | ver=2(1) | kdf=1 Argon2id(1) | mem KiB(4) | iters(1) | par(1) | salt(32) | nonce(12) | ciphertext+tag
```

## Dependencies

Only **BouncyCastle** (Argon2id, pure Java). No networking, no Google services, no Tink, no
other third-party crypto frameworks. The module declares **no permissions and no components**.

## Run the tests

```bash
./gradlew :crypto:test                  # unit (JVM, no device)
./gradlew :crypto:connectedAndroidTest  # instrumented (device/emulator, screen unlocked)
```

The suite includes official known-answer vectors — HKDF-SHA256 (RFC 5869, TC1–3) and Argon2id
(RFC 9106 §5.3) — so you can confirm the primitives match the standards rather than taking our
word for it. Full coverage map, vectors and manual checks: [TESTING.md](TESTING.md). Reports go
to `crypto/build/` and are gitignored: **results are reproduced by running, not stored in a file.**

## Reproduce a check in 30 seconds

```kotlin
// Authenticated backup encryption round-trips, and any tamper fails closed:
val blob = BackupCrypto.encrypt("secret".toByteArray(), "correct horse battery staple")
check(BackupCrypto.decrypt(blob, "correct horse battery staple")!!.decodeToString() == "secret")
check(BackupCrypto.decrypt(blob, "wrong password") == null)          // wrong key → null
blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 1).toByte()
check(BackupCrypto.decrypt(blob, "correct horse battery staple") == null) // tamper → null
```

See `RoundTripTest`, `KnownAnswerTest`, `AeadIntegrityTest`, `BackupIntegrityTest` for the
exhaustive versions.
