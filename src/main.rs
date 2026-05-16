use aes_gcm::{
    AeadCore, Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

const NONCE_LEN: usize = 12;

fn derive_key(password: &[u8]) -> aes_gcm::Key<Aes256Gcm> {
    let mut hasher = Sha256::new();
    hasher.update(password);
    let result = hasher.finalize();
    aes_gcm::Key::<Aes256Gcm>::from_slice(&result).to_owned()
}

fn encryption(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| "encryption failed".to_string())?;

    let mut finaltext = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    finaltext.extend_from_slice(nonce.as_slice());
    finaltext.extend_from_slice(&ciphertext);
    Ok(finaltext)
}

fn decryption(data: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < NONCE_LEN {
        return Err("ciphertext is incomplete".to_string());
    }
    let nonce_bytes = &data[0..NONCE_LEN];
    let ciphertext_bytes = &data[NONCE_LEN..];

    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext_bytes)
        .map_err(|_| "decryption failed (wrong password or corrupted data)".to_string())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        eprintln!();
        eprintln!("{}", usage());
        std::process::exit(1);
    }
}

fn read_password() -> Vec<u8> {
    eprint!("password: ");
    let _ = io::stderr().flush();

    // 如果 stdin 不是 TTY（比如从程序管道输入），就读一行
    if !atty::is(atty::Stream::Stdin) {
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            return input.trim_end().as_bytes().to_vec();
        }
        return Vec::new();
    }

    match rpassword::read_password() {
        Ok(input) => input.trim_end().as_bytes().to_vec(),
        Err(_) => Vec::new(),
    }
}

fn usage() -> &'static str {
    "Usage:\n  jen encrypt <plaintext_path> <ciphertext_path>\n  jen decrypt <ciphertext_path>\n\nExamples:\n  jen encrypt message.txt message.enc\n  jen decrypt message.enc"
}

fn run() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() < 2 {
        return Err("missing method".to_string());
    }

    if args[1] == "encrypt" {
        if args.len() < 4 {
            return Err("missing plaintext or ciphertext path".to_string());
        }
        let plaintext =
            std::fs::read(&args[2]).map_err(|err| format!("failed to read plaintext: {err}"))?;
        let password = read_password();
        let finaltext = encryption(&plaintext, &password)?;
        std::fs::write(&args[3], &finaltext)
            .map_err(|err| format!("failed to write ciphertext: {err}"))?;
        Ok(())
    } else if args[1] == "decrypt" {
        if args.len() < 3 {
            return Err("missing ciphertext path".to_string());
        }
        let ciphertext =
            std::fs::read(&args[2]).map_err(|err| format!("failed to read ciphertext: {err}"))?;
        let password = read_password();
        let plaintext = decryption(&ciphertext, &password)?;
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(&plaintext)
            .map_err(|err| format!("failed to write plaintext: {err}"))?;
        Ok(())
    } else {
        Err("unknown method: use encrypt or decrypt".to_string())
    }
}
