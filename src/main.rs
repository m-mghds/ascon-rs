use ascon_rs::aead;
use ascon_rs::key::Key;

use std::io::{self, Write};

fn main() {
    println!("ASCON-AEAD128 Demo");
    println!("1) Default encrypt/decrypt demo");
    println!("2) Encrypt custom input");
    println!("3) Decrypt custom input");

    let choice = read_line("Select option: ");

    match choice.trim() {
        "1" => run_default_demo(),
        "2" => run_custom_encrypt(),
        "3" => run_custom_decrypt(),
        _ => println!("Invalid option."),
    }
}

fn run_default_demo() {
    let key = Key::from_bytes([0u8; 16]);
    let nonce = [0u8; 16];

    let ad = b"demo associated data";
    let plaintext = b"Hello, Ascon-AEAD128!";

    let mut ciphertext = vec![0u8; plaintext.len()];

    let tag =
        aead::encrypt(&key, &nonce, ad, plaintext, &mut ciphertext).expect("encryption failed");

    let mut recovered = vec![0u8; ciphertext.len()];

    aead::decrypt(&key, &nonce, ad, &ciphertext, &tag, &mut recovered)
        .expect("authentication failed");

    println!("\nPlaintext:");
    println!("{}", String::from_utf8_lossy(plaintext));

    println!("\nAssociated Data:");
    println!("{}", String::from_utf8_lossy(ad));

    println!("\nCiphertext:");
    print_hex(&ciphertext);

    println!("\nTag:");
    print_hex(&tag);

    println!("\nCiphertext || Tag:");
    print_hex_no_newline(&ciphertext);
    print_hex(&tag);

    println!("\nRecovered Plaintext:");
    println!("{}", String::from_utf8_lossy(&recovered));
}

fn run_custom_encrypt() {
    let key_hex = read_line("Key hex, 16 bytes / 32 hex chars: ");
    let nonce_hex = read_line("Nonce hex, 16 bytes / 32 hex chars: ");
    let ad_hex = read_line("AD hex, can be empty: ");
    let pt_hex = read_line("Plaintext hex, can be empty: ");

    let key_bytes = match parse_hex_array::<16>(&key_hex) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid key: {e}");
            return;
        }
    };

    let nonce = match parse_hex_array::<16>(&nonce_hex) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid nonce: {e}");
            return;
        }
    };

    let ad = match parse_hex(&ad_hex) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid AD: {e}");
            return;
        }
    };

    let plaintext = match parse_hex(&pt_hex) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid plaintext: {e}");
            return;
        }
    };

    let key = Key::from_bytes(key_bytes);
    let mut ciphertext = vec![0u8; plaintext.len()];

    let tag = match aead::encrypt(&key, &nonce, &ad, &plaintext, &mut ciphertext) {
        Ok(tag) => tag,
        Err(e) => {
            println!("Encryption failed: {:?}", e);
            return;
        }
    };

    println!("\nCiphertext:");
    print_hex(&ciphertext);

    println!("\nTag:");
    print_hex(&tag);

    println!("\nKAT-style CT = Ciphertext || Tag:");
    print_hex_no_newline(&ciphertext);
    print_hex(&tag);
}

fn run_custom_decrypt() {
    let key_hex = read_line("Key hex, 16 bytes / 32 hex chars: ");
    let nonce_hex = read_line("Nonce hex, 16 bytes / 32 hex chars: ");
    let ad_hex = read_line("AD hex, can be empty: ");
    let ct_hex = read_line("Ciphertext hex, without tag: ");
    let tag_hex = read_line("Tag hex, 16 bytes / 32 hex chars: ");

    let key_bytes = match parse_hex_array::<16>(&key_hex) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid key: {e}");
            return;
        }
    };

    let nonce = match parse_hex_array::<16>(&nonce_hex) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid nonce: {e}");
            return;
        }
    };

    let ad = match parse_hex(&ad_hex) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid AD: {e}");
            return;
        }
    };

    let ciphertext = match parse_hex(&ct_hex) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid ciphertext: {e}");
            return;
        }
    };

    let tag = match parse_hex_array::<16>(&tag_hex) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid tag: {e}");
            return;
        }
    };

    let key = Key::from_bytes(key_bytes);
    let mut plaintext = vec![0u8; ciphertext.len()];

    let result = aead::decrypt(&key, &nonce, &ad, &ciphertext, &tag, &mut plaintext);

    match result {
        Ok(()) => {
            println!("\nAuthentication: OK");

            println!("\nPlaintext hex:");
            print_hex(&plaintext);

            println!("\nPlaintext as UTF-8, if readable:");
            println!("{}", String::from_utf8_lossy(&plaintext));
        }
        Err(e) => {
            println!("\nDecryption failed: {:?}", e);
            println!("The tag is invalid, or one of key/nonce/AD/ciphertext is wrong.");
        }
    }
}

fn read_line(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().expect("failed to flush stdout");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("failed to read line");

    input.trim().to_string()
}

fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    if clean.is_empty() {
        return Ok(Vec::new());
    }

    if clean.len() % 2 != 0 {
        return Err("hex string must have an even number of characters".to_string());
    }

    let mut bytes = Vec::with_capacity(clean.len() / 2);

    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|_| format!("invalid hex byte: {}", &clean[i..i + 2]))?;

        bytes.push(byte);
    }

    Ok(bytes)
}

fn parse_hex_array<const N: usize>(input: &str) -> Result<[u8; N], String> {
    let bytes = parse_hex(input)?;

    if bytes.len() != N {
        return Err(format!("expected {N} bytes, got {} bytes", bytes.len()));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);

    Ok(out)
}

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{:02x}", byte);
    }
    println!();
}

fn print_hex_no_newline(bytes: &[u8]) {
    for byte in bytes {
        print!("{:02x}", byte);
    }
}
