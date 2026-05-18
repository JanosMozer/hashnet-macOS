use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use notify::event::{CreateKind, ModifyKind, RemoveKind, RenameMode};
use sha2::{Digest, Sha256};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as Base64Url;
use base64::Engine;
use chacha20poly1305::{ChaCha20Poly1305, aead::{Aead, AeadCore, KeyInit, OsRng}};
use tracing::{error, info};
use anyhow::Result;

use crate::{Manifest, ManifestEntry};

pub struct FileWatcher {
    _watcher: RecommendedWatcher,
}

/// Start watching ~/Hashnet/encrypted/ and process events via the shared state.
pub fn start(
    watch_dir: PathBuf,
    state: Arc<RwLock<super::DaemonState>>,
) -> Result<FileWatcher> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    })?;

    watcher.watch(&watch_dir, RecursiveMode::Recursive)?;
    info!("Watching {:?} for filesystem events", watch_dir);

    let watch_dir_scan = watch_dir.clone();
    tokio::spawn(async move {
        // Startup scan: queue any existing plaintext files for encryption
        let existing: Vec<PathBuf> = walkdir::WalkDir::new(&watch_dir_scan)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| !is_enc(p) && !is_tmp(p) && !is_manifest(p))
            .collect();
        if !existing.is_empty() {
            info!("Startup scan found {} plaintext file(s) to encrypt", existing.len());
            let mut s = state.write().await;
            for path in existing {
                info!("  queuing for encryption: {:?}", path.file_name());
                s.pending_encrypt.push_back(path);
            }
        }

        while let Some(event) = rx.recv().await {
            handle_event(event, &state).await;
        }
    });

    Ok(FileWatcher { _watcher: watcher })
}

async fn handle_event(event: Event, state: &Arc<RwLock<super::DaemonState>>) {
    let all_paths = event.paths.clone();
    let paths: Vec<PathBuf> = event.paths.iter()
        .filter(|p| !is_enc(p) && !is_tmp(p) && !is_new(p) && !is_manifest(p))
        .cloned()
        .collect();

    info!("FSEvent {:?} paths={:?}", event.kind, all_paths.iter().map(|p| p.file_name()).collect::<Vec<_>>());

    match event.kind {
        EventKind::Create(CreateKind::File) => {
            for path in paths {
                encrypt_file_from_watcher(path, state).await;
            }
        }
        EventKind::Create(CreateKind::Folder) => {
            for dir in paths {
                let entries: Vec<PathBuf> = walkdir::WalkDir::new(&dir)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .map(|e| e.into_path())
                    .filter(|p| !is_enc(p))
                    .collect();
                for path in entries {
                    encrypt_file_from_watcher(path, state).await;
                }
            }
        }
        EventKind::Modify(ModifyKind::Data(_)) => {
            for path in paths {
                let changed = {
                    let s = state.read().await;
                    file_hash_changed(&path, &s.manifest)
                };
                if changed {
                    encrypt_file_from_watcher(path, state).await;
                }
            }
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) if all_paths.len() >= 2 => {
            let from = &all_paths[0];
            let to = &all_paths[1];
            if !is_enc(from) && !is_enc(to) {
                // Plaintext moved within the watch dir — encrypt it at new location
                encrypt_file_from_watcher(to.clone(), state).await;
            } else if is_enc(from) && !is_enc(to) {
                // .enc renamed to plaintext — re-encrypt
                encrypt_file_from_watcher(to.clone(), state).await;
            } else {
                // .enc renamed — update manifest key
                let mut s = state.write().await;
                if let Some(entry) = s.manifest.files.remove(&from.to_string_lossy().to_string()) {
                    s.manifest.files.insert(to.to_string_lossy().to_string(), entry);
                    let _ = save_manifest(&s.manifest);
                }
            }
        }
        EventKind::Remove(RemoveKind::File) => {
            let mut s = state.write().await;
            for path in &event.paths {
                s.manifest.files.remove(&path.to_string_lossy().to_string());
                s.in_flight.remove(path);
            }
            let _ = save_manifest(&s.manifest);
        }
        _ => {}
    }
}

pub async fn encrypt_file_from_watcher_pub(path: PathBuf, state: &Arc<RwLock<super::DaemonState>>) {
    encrypt_file_from_watcher(path, state).await;
}

async fn encrypt_file_from_watcher(path: PathBuf, state: &Arc<RwLock<super::DaemonState>>) {
    info!("encrypt_file_from_watcher: {:?}", path.file_name());
    // Gate: check in-flight and PNK availability under a single read lock
    let pnk_bytes = {
        let s = state.read().await;
        if s.in_flight.contains(&path) {
            info!("  -> already in-flight, skipping");
            return;
        }
        if s.pnk.is_none() {
            info!("  -> PNK not ready, queuing");
        }
        s.pnk.as_ref().map(|p| p.0)
    };

    let Some(key_bytes) = pnk_bytes else {
        // PNK not ready — queue for later
        let mut s = state.write().await;
        s.pending_encrypt.push_back(path);
        return;
    };

    // Mark in-flight
    {
        let mut s = state.write().await;
        s.in_flight.insert(path.clone());
    }

    match do_encrypt(&path, &key_bytes).await {
        Ok((enc_path, entry)) => {
            let mut s = state.write().await;
            s.in_flight.remove(&path);
            s.manifest.files.insert(enc_path.to_string_lossy().to_string(), entry);
            let _ = save_manifest(&s.manifest);
            info!("Encrypted {:?} -> {:?}", path.file_name(), enc_path.file_name());
        }
        Err(e) => {
            let mut s = state.write().await;
            s.in_flight.remove(&path);
            let err_str = e.to_string();
            if err_str.contains("No such file") {
                info!("File already encrypted or deleted: {:?}", path.file_name());
            } else {
                error!("Failed to encrypt {:?}: {}", path, e);
            }
        }
    }
}

/// Core encryption: read → encrypt → atomic write → delete plaintext
pub async fn do_encrypt(path: &Path, key_bytes: &[u8; 32]) -> Result<(PathBuf, ManifestEntry)> {
    let data = tokio::fs::read(path).await?;
    let meta = tokio::fs::metadata(path).await?;

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = Base64Url.encode(hasher.finalize());

    let cipher = ChaCha20Poly1305::new(key_bytes.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let encrypted = cipher.encrypt(&nonce, data.as_ref())
        .map_err(|_| anyhow::anyhow!("ChaCha20 encryption failed"))?;

    let mut enc_data = nonce.to_vec();
    enc_data.extend(encrypted);

    // Write to tmp first for atomicity
    let enc_name = format!("{}.enc", &hash[..20]);
    let enc_dir = path.parent().unwrap_or(path);
    let tmp_path = enc_dir.join(format!(".{}.tmp", &hash[..20]));
    let enc_path = enc_dir.join(&enc_name);

    tokio::fs::write(&tmp_path, &enc_data).await?;
    tokio::fs::rename(&tmp_path, &enc_path).await?;
    tokio::fs::remove_file(path).await?;

    let entry = ManifestEntry {
        original_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        original_path: path.to_string_lossy().to_string(),
        inode: meta.ino(),
        sha256_original: hash,
        encrypted_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        size_bytes: data.len() as u64,
    };

    Ok((enc_path, entry))
}

/// Decrypt a .enc file to a temp path and return it. Caller is responsible for opening/cleanup.
pub async fn do_decrypt(enc_path: &Path, key_bytes: &[u8; 32], original_name: &str) -> Result<std::path::PathBuf> {
    let data = tokio::fs::read(enc_path).await?;
    if data.len() < 12 {
        anyhow::bail!("encrypted file too short");
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    if nonce_bytes.len() != 12 {
        anyhow::bail!("invalid nonce length");
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce_bytes);
    let nonce = chacha20poly1305::Nonce::from(nonce_arr);
    let cipher = ChaCha20Poly1305::new(key_bytes.into());
    let plaintext = cipher.decrypt(&nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong key or corrupted file"))?;

    let tmp_dir = std::env::temp_dir().join("hashnet-open");
    tokio::fs::create_dir_all(&tmp_dir).await?;
    let out_path = tmp_dir.join(original_name);
    tokio::fs::write(&out_path, &plaintext).await?;
    info!("Decrypted {:?} -> {:?}", enc_path.file_name(), out_path.file_name());
    Ok(out_path)
}

fn file_hash_changed(path: &Path, manifest: &Manifest) -> bool {
    // Find manifest entry by original_path
    let path_str = path.to_string_lossy();
    let stored_hash = manifest.files.values()
        .find(|e| e.original_path == path_str.as_ref())
        .map(|e| &e.sha256_original);

    let Ok(data) = std::fs::read(path) else { return false };
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let current = Base64Url.encode(hasher.finalize());

    stored_hash.map_or(true, |h| h != &current)
}

fn is_enc(p: &Path) -> bool {
    p.extension().map_or(false, |e| e == "enc")
}

fn is_tmp(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map_or(false, |n| n.starts_with('.') && n.ends_with(".tmp"))
}

fn is_new(p: &Path) -> bool {
    p.extension().map_or(false, |e| e == "new")
}

fn is_manifest(p: &Path) -> bool {
    p.ends_with(".hashnet/manifest.json")
}

/// Re-encrypt all .enc files with a new PNK. Safe two-phase write: .enc.new files first,
/// then atomic rename if all succeed. Returns count of files re-encrypted or error.
pub async fn re_encrypt_all(
    manifest: Arc<tokio::sync::Mutex<Manifest>>,
    old_pnk: &[u8; 32],
    new_pnk: &[u8; 32],
) -> Result<usize, String> {
    // 1. Snapshot manifest entries
    let snapshot = {
        let m = manifest.lock().await;
        m.files.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>()
    };

    info!("re_encrypt_all: starting re-encryption of {} files", snapshot.len());

    let mut new_files = Vec::new();

    // 2. Write all .enc.new temp files
    for (enc_path_str, _entry) in &snapshot {
        let enc_path = std::path::PathBuf::from(enc_path_str);
        let new_enc_path = enc_path.with_extension("enc.new");

        // Read encrypted file
        let data = match tokio::fs::read(&enc_path).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File deleted after snapshot — skip
                info!("  File {} no longer exists, skipping", enc_path_str);
                continue;
            }
            Err(e) => {
                let err_msg = format!("Failed to read {}: {}", enc_path_str, e);
                error!("{}", err_msg);
                // Clean up any .new files written so far
                for (_, new_path) in &new_files {
                    let _ = tokio::fs::remove_file(new_path).await;
                }
                return Err(err_msg);
            }
        };

        // Decrypt with old PNK
        if data.len() < 12 {
            let err_msg = format!("File {} too short for nonce", enc_path_str);
            error!("{}", err_msg);
            for (_, new_path) in &new_files {
                let _ = tokio::fs::remove_file(new_path).await;
            }
            return Err(err_msg);
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce_bytes);
        let nonce = chacha20poly1305::Nonce::from(nonce_arr);

        let cipher_old = ChaCha20Poly1305::new(old_pnk.into());
        let plaintext = match cipher_old.decrypt(&nonce, ciphertext) {
            Ok(p) => p,
            Err(_) => {
                let err_msg = format!("Decryption failed for {} (wrong key or corrupted)", enc_path_str);
                error!("{}", err_msg);
                for (_, new_path) in &new_files {
                    let _ = tokio::fs::remove_file(new_path).await;
                }
                return Err(err_msg);
            }
        };

        // Re-encrypt with new PNK
        let cipher_new = ChaCha20Poly1305::new(new_pnk.into());
        let new_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted = match cipher_new.encrypt(&new_nonce, plaintext.as_ref()) {
            Ok(e) => e,
            Err(_) => {
                let err_msg = format!("Re-encryption failed for {}", enc_path_str);
                error!("{}", err_msg);
                for (_, new_path) in &new_files {
                    let _ = tokio::fs::remove_file(new_path).await;
                }
                return Err(err_msg);
            }
        };

        // Write new .enc.new file
        let mut enc_data = new_nonce.to_vec();
        enc_data.extend(encrypted);

        if let Err(e) = tokio::fs::write(&new_enc_path, &enc_data).await {
            let err_msg = format!("Failed to write {}: {}", new_enc_path.display(), e);
            error!("{}", err_msg);
            for (_, new_path) in &new_files {
                let _ = tokio::fs::remove_file(new_path).await;
            }
            return Err(err_msg);
        }

        new_files.push((enc_path.clone(), new_enc_path));
    }

    // 3. All .new files written successfully — now commit the swap
    for (old_path, new_path) in &new_files {
        if let Err(e) = tokio::fs::rename(new_path, old_path).await {
            let err_msg = format!("Failed to rename {} -> {}: {}", new_path.display(), old_path.display(), e);
            error!("{}", err_msg);
            // Best effort cleanup of remaining .new files
            for (_, np) in &new_files {
                let _ = tokio::fs::remove_file(np).await;
            }
            return Err(err_msg);
        }
    }

    // 4. Update manifest with new timestamps (plaintext content unchanged, so SHA256 unchanged)
    {
        let mut m = manifest.lock().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (enc_path_str, entry) in m.files.iter_mut() {
            if snapshot.iter().any(|(k, _)| k == enc_path_str) {
                entry.encrypted_at = now;
            }
        }
    }

    // 5. Save manifest
    let manifest_locked = manifest.lock().await;
    if let Err(e) = save_manifest(&*manifest_locked) {
        error!("Failed to save manifest after re-encryption: {}", e);
        return Err(format!("Failed to save manifest: {}", e));
    }

    info!("re_encrypt_all: successfully re-encrypted {} files", new_files.len());
    Ok(new_files.len())
}

pub fn save_manifest(manifest: &Manifest) -> Result<()> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home dir"))?;
    let path = home.join("Hashnet/.hashnet/manifest.json");
    let json = serde_json::to_string_pretty(manifest)?;
    std::fs::write(path, json)?;
    Ok(())
}
