use ascon_rs::aead;
use ascon_rs::key::Key;

fn main() {
    let key = Key::from_bytes([0u8; 16]);
    let nonce = [0u8; 16];

    let ad = b"example metadata";
    let plaintext = b"Hello, Ascon-AEAD128!";

    let mut ciphertext = [0u8; 21];

    let tag = aead::encrypt(&key, &nonce, ad, plaintext, &mut ciphertext)
        .expect("ciphertext buffer length must match plaintext length");

    println!("Ciphertext:");
    print_hex(&ciphertext);

    println!("Tag:");
    print_hex(&tag);
}

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{:02x}", byte);
    }
    println!();
}
