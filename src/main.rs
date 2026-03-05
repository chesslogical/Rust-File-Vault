#![allow(deprecated)]

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use rpassword::read_password;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

// ================= CONFIGURATION =================
// File size limit for processing (adjust based on RAM)
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB default
// Example for large RAM systems:
// const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10 GB
// =================================================

const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() {
    println!("=== File Vault ===\n");

    if let Err(e) = ensure_vault_dir() {
        println!("Error creating vault directory: {}", e);
        return;
    }

    loop {
        println!("\nChoose an option:");
        println!("1. Encrypt a file");
        println!("2. Decrypt a file");
        println!("3. List encrypted files");
        println!("4. Exit");
        print!("\nEnter choice: ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        let result = match choice.trim() {
            "1" => encrypt_file(),
            "2" => decrypt_file(),
            "3" => list_files(),
            "4" => {
                println!("Goodbye!");
                break;
            }
            _ => {
                println!("Invalid choice.");
                continue;
            }
        };

        if let Err(e) = result {
            println!("Error: {}", e);
        }
    }
}

fn ensure_vault_dir() -> Result<()> {
    let vault_dir = Path::new("vault");
    if !vault_dir.exists() {
        fs::create_dir(vault_dir)?;
        println!("Created vault directory");
    }
    Ok(())
}

fn get_files_in_dir(dir: &Path, extensions: &[&str]) -> Result<Vec<String>> {
    let entries = fs::read_dir(dir)?;
    let mut files = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(filename) = path.file_name() {
                let filename_str = filename.to_string_lossy().to_string();
                let valid_ext = extensions.is_empty()
                    || extensions.iter().any(|ext| filename_str.ends_with(ext));

                if valid_ext
                    && !filename_str.ends_with(".exe")
                    && !filename_str.starts_with(".")
                    && filename_str != "Cargo.toml"
                    && filename_str != "Cargo.lock"
                {
                    files.push(filename_str);
                }
            }
        }
    }
    Ok(files)
}

fn get_argon2() -> Result<Argon2<'static>> {
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| format!("Argon2 params error: {}", e))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn sanitize_filename(name: &str) -> Result<String> {
    let path = Path::new(name);
    let file = path
        .file_name()
        .ok_or("Invalid filename")?
        .to_string_lossy()
        .to_string();

    if file.contains('/') || file.contains('\\') {
        return Err("Invalid filename".into());
    }
    Ok(file)
}

fn get_password_with_confirmation() -> Result<String> {
    loop {
        print!("Enter password: ");
        io::stdout().flush()?;
        let mut password = read_password()?;

        print!("Confirm password: ");
        io::stdout().flush()?;
        let mut confirm = read_password()?;

        if password == confirm {
            confirm.zeroize();
            return Ok(password);
        } else {
            println!("Passwords do not match.\n");
            password.zeroize();
            confirm.zeroize();
        }
    }
}

fn get_password() -> Result<String> {
    print!("Enter password: ");
    io::stdout().flush()?;
    Ok(read_password()?)
}

fn select_file_from_list(files: &[String], prompt: &str) -> Result<String> {
    if files.is_empty() {
        return Err("No files available".into());
    }

    println!("\n{}:", prompt);
    for (i, file) in files.iter().enumerate() {
        println!("  {}. {}", i + 1, file);
    }

    print!("\nEnter file number: ");
    io::stdout().flush()?;

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let index: usize = choice.trim().parse().map_err(|_| "Invalid number")?;

    if index == 0 || index > files.len() {
        return Err("Invalid selection".into());
    }

    Ok(files[index - 1].clone())
}

fn check_file_size(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(format!(
            "File too large (limit {} bytes)",
            MAX_FILE_SIZE
        )
        .into());
    }
    Ok(())
}

fn encrypt_file() -> Result<()> {
    println!("\n=== Encrypt File ===");

    let current_dir = std::env::current_dir()?;
    let files = get_files_in_dir(&current_dir, &[])?;
    let files: Vec<String> = files
        .into_iter()
        .filter(|f| !f.ends_with(".vault"))
        .collect();

    if files.is_empty() {
        return Err("No files found".into());
    }

    let filename = select_file_from_list(&files, "Available files")?;
    let path = PathBuf::from(&filename);
    check_file_size(&path)?;

    let data = fs::read(&path)?;

    let mut password = get_password_with_confirmation()?;

    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let argon2 = get_argon2()?;
    let mut key = [0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;
    password.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher creation failed: {:?}", e))?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    key.zeroize();

    let mut output = Vec::new();
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    let safe_name = sanitize_filename(&filename)?;
    let output_path = format!("vault/{}.vault", safe_name);
    fs::write(&output_path, output)?;

    println!("Encrypted file saved: {}", output_path);
    fs::remove_file(&filename)?;
    println!("Original file deleted");

    Ok(())
}

fn decrypt_file() -> Result<()> {
    println!("\n=== Decrypt File ===");

    let vault_dir = Path::new("vault");
    let files = get_files_in_dir(vault_dir, &[".vault"])?;
    if files.is_empty() {
        return Err("No encrypted files found".into());
    }

    let filename = select_file_from_list(&files, "Encrypted files")?;
    let path = vault_dir.join(&filename);
    check_file_size(&path)?;

    let encrypted_data = fs::read(&path)?;
    if encrypted_data.len() < SALT_SIZE + NONCE_SIZE {
        return Err("Invalid encrypted file".into());
    }

    let salt = &encrypted_data[0..SALT_SIZE];
    let nonce_bytes = &encrypted_data[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ciphertext = &encrypted_data[SALT_SIZE + NONCE_SIZE..];

    let mut password = get_password()?;
    let argon2 = get_argon2()?;
    let mut key = [0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;
    password.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher creation failed: {:?}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed (wrong password or corrupted file)")?;
    key.zeroize();

    let safe_name = sanitize_filename(
        filename
            .strip_suffix(".vault")
            .ok_or("Invalid vault filename")?,
    )?;
    fs::write(&safe_name, plaintext)?;
    println!("Decrypted file saved: {}", safe_name);

    fs::remove_file(&path)?;
    println!("Encrypted file deleted");

    Ok(())
}

fn list_files() -> Result<()> {
    println!("\n=== Encrypted Files ===");

    let vault_dir = Path::new("vault");
    if !vault_dir.exists() {
        println!("Vault directory missing");
        return Ok(());
    }

    let files = get_files_in_dir(vault_dir, &[".vault"])?;
    if files.is_empty() {
        println!("No encrypted files");
        return Ok(());
    }

    for file in files {
        let path = vault_dir.join(&file);
        let size = fs::metadata(&path)?.len();
        println!("{} ({} bytes)", file, size);
    }

    Ok(())
}
