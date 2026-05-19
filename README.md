# Hashnet Tray Client (macOS)

A high-performance, Zero-Trust local encryption daemon and system tray client for macOS, featuring Secure Hardware Storage (Keychain), background presence, dynamic key rotation, and local file watch encryption.

```
+-----------------------------------------------------------+
|                      System Tray Client                   |
|   - Translucent glassmorphic menu bar frontend (Tauri)    |
|   - Smooth 150ms requestAnimationFrame window sizing      |
|   - Instantly reactive accordion layout panels            |
+-----------------------------------------------------------+
                             |
                   IPC Unix Socket (/tmp/csi.sock)
                             |
                             v
+-----------------------------------------------------------+
|                     csid Daemon Process                   |
|   - File watcher and auto-encryption pipeline             |
|   - Clerk OAuth PKCE loop and device presence heartbeats  |
|   - macOS Keychain integration for Hardware Identities   |
|   - Supabase Key Broker synchronization protocols         |
+-----------------------------------------------------------+
```

---

## Key Features

* **Zero-Trust Encryption:** Files inside the `~/Hashnet/` folder are automatically encrypted using a Personal Network Key (PNK) that never leaves trusted execution context unencrypted.
* **Secure Enclave / Keychain Storage:** Hardware Identifiers (HIK) and active Personal Network Keys (PNK) are stored inside the macOS Secure Keychain, fully isolating secrets from local disk.
* **Auto-Rotation:** Dynamic rotation protocols automatically renew the PNK periodically and push encrypted key wrappers to the database key broker for active user devices.
* **Presence & Heartbeats:** Dynamic active presence updates (`is_active` / `last_seen_at`) and automatic offline teardown handling on SIGINT/SIGTERM gracefully manage presence.
* **High-Density Tray Interface:** Translucent macOS-style inset menu lists with system orange highlights, frame-perfect window bounds rendering at 120fps, and dynamic height animations.

---

## Architectural Layout

* **`/csi-core`**: Shared cryptography wrappers (X25519 key encapsulation, symmetric file encryption) and Keychain storage integrations.
* **`/csi-ipc`**: Strongly-typed JSON IPC socket request/response schemas.
* **`/csid`**: The persistent background coordinator daemon, managing socket listener, Supabase sync, OAuth callback loop, and the `~/Hashnet` directory file watcher.
* **`/csi-tray`**: Borderless, glassmorphic Tauri system-tray application.

---

## Build & Running Specs

### Prerequisites
* Rust Toolchain (stable)
* Node.js & Bun (for frontend dev server if building alongside app)
* A running Supabase instance with schema applied (see `database.sql`)

### Setup Environment
Create a `.env` file in the root directory:
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-service-role-key
```

### Run Background Daemon
In a dedicated terminal:
```bash
cargo run --bin csid
```

### Run Tray Frontend
In a secondary terminal:
```bash
cargo run --bin csi-tray
```

---