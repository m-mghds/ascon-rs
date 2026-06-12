use ascon_rs::aead;
use ascon_rs::key::Key;

fn main() {
    // Demo-only key and nonce.
    // Do not hardcode real keys/nonces in real applications.
    let key = Key::from_bytes([0u8; 16]);
    let nonce = [0u8; 16];

    let ad = b"demo associated data";
    let plaintext = b"Hello, Ascon-AEAD128!";

    let mut ciphertext = [0u8; 21];

    let tag = aead::encrypt(
        &key,
        &nonce,
        ad,
        plaintext,
        &mut ciphertext,
    )
    .expect("ciphertext buffer length must match plaintext length");

    let mut recovered = [0u8; 21];

    aead::decrypt(
        &key,
        &nonce,
        ad,
        &ciphertext,
        &tag,
        &mut recovered,
    )
    .expect("authentication failed");

    println!("Plaintext:");
    println!("{}", core::str::from_utf8(plaintext).unwrap());

    println!("\nCiphertext:");
    print_hex(&ciphertext);

    println!("\nTag:");
    print_hex(&tag);

    println!("\nRecovered plaintext:");
    println!("{}", core::str::from_utf8(&recovered).unwrap());
}

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{:02x}", byte);
    }
    println!();
}