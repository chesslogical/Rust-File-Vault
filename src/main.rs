#![allow(deprecated)]
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
use rpassword::read_password;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroize;

const SALT_SIZE: usize = 32; //256 bits for Argon2 salt
const NONCE_SIZE: usize = 12; //96 bits is standard/recommended for GCM

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
                println!("Invalid choice, try again.");
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
        println!("Created vault directory\n");
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
                let has_valid_ext = extensions.is_empty()
                    || extensions.iter().any(|ext| filename_str.ends_with(ext));

                if has_valid_ext //allows all user files to be uploaded, excludes vault to not double encrypt
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

fn get_password_with_confirmation() -> Result<String> {
    loop {
        print!("Enter password: ");
        io::stdout().flush()?;
        let mut password = read_password()?;

        print!("Confirm password: ");
        io::stdout().flush()?;
        let mut confirm = read_password()?;

        if password == confirm {
            println!("Passwords match");
            confirm.zeroize(); //zeroising passwords overwrites their plaintext contents in memory
            drop(confirm); //explicitly drop to free memory immediately
            return Ok(password);
        } else {
            println!("Passwords don't match, try again\n");
            password.zeroize();
            drop(password);
            confirm.zeroize();
            drop(confirm);
        }
    }
}

fn get_password() -> Result<String> {
    print!("Enter password: ");
    io::stdout().flush()?;
    let password = read_password()?;
    Ok(password)
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

    let file_index: usize = choice
        .trim()
        .parse::<usize>()
        .map_err(|_| "Invalid number")?;

    if file_index == 0 || file_index > files.len() {
        return Err("Invalid selection".into());
    }

    Ok(files[file_index - 1].clone())
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
        return Err("No files found to encrypt in current directory".into());
    }

    let filename = select_file_from_list(&files, "Available files")?;
    let data = fs::read(&filename)?;
    let mut password = get_password_with_confirmation()?;

    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let mut key = [0u8; 32];
    //32-byte output matches AES-256 key size
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;
    password.zeroize();

    println!("Encrypting...");
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher creation failed: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    key.zeroize(); //zeroises after encryption

    let mut output = Vec::new(); //file layout: [salt:32][nonce:12][ciphertext+tag:variable]
    output.extend_from_slice(&salt); //unique per file
    output.extend_from_slice(&nonce_bytes); //unique per encryption operation
    output.extend_from_slice(&ciphertext);

    let path_obj = Path::new(&filename);
    let full_filename = path_obj
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid filename")?;
    let output_path = format!("vault/{}.vault", full_filename);
    fs::write(&output_path, output)?;

    println!("\nEncryption complete!");
    println!("Encrypted file saved: {}", output_path);

    fs::remove_file(&filename)?;
    println!("Original file deleted");

    Ok(())
}

fn decrypt_file() -> Result<()> {
    println!("\n=== Decrypt File ===");

    let vault_dir = Path::new("vault");
    if !vault_dir.exists() {
        return Err("Vault directory doesn't exist yet".into());
    }

    let files = get_files_in_dir(vault_dir, &[".vault"])?;
    if files.is_empty() {
        return Err("No encrypted files found in vault".into());
    }

    let filename = select_file_from_list(&files, "Encrypted files in vault")?;
    let path = format!("vault/{}", filename);
    let encrypted_data = fs::read(&path)?;

    if encrypted_data.len() < SALT_SIZE + NONCE_SIZE {
        return Err("File is too small to be valid encrypted data".into());
    }

    let salt = &encrypted_data[0..SALT_SIZE];
    let nonce_bytes = &encrypted_data[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ciphertext = &encrypted_data[SALT_SIZE + NONCE_SIZE..];

    let mut password = get_password()?;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;
    password.zeroize();

    println!("Decrypting...");
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher creation failed: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed! Wrong password or corrupted file")?;
    key.zeroize();

    let path_obj = Path::new(&path);
    let filename_with_vault = path_obj
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid filename")?;
    let original_filename = filename_with_vault
        .strip_suffix(".vault")
        .ok_or("Invalid vault filename")?;
    fs::write(original_filename, plaintext)?;

    println!("\nDecryption complete!");
    println!("Decrypted file saved: {}", original_filename);

    fs::remove_file(&path)?;
    println!("Encrypted file deleted from vault");

    Ok(())
}

fn list_files() -> Result<()> {
    println!("\n=== Encrypted Files in Vault ===");

    let vault_dir = Path::new("vault");
    if !vault_dir.exists() {
        println!("  Vault directory doesn't exist yet.");
        return Ok(());
    }

    let files = get_files_in_dir(vault_dir, &[".vault"])?;
    if files.is_empty() {
        println!("  No encrypted files found in vault.");
        return Ok(());
    }

    for file in files {
        let path = format!("vault/{}", file);
        let metadata = fs::metadata(&path)?;
        let size = metadata.len();
        println!("  {} ({} bytes)", file, size);
    }

    Ok(())
}
