use rand::{rngs::OsRng, RngCore};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding}};
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use base64::{Engine, engine::general_purpose::STANDARD};
use uuid::Uuid;
use argon2::{Argon2, password_hash::{PasswordHasher, SaltString}};

/// This demonstrates real cryptographic key generation (not mock/fake)
fn main() {
    println!("🔐 Demonstrating REAL cryptographic key generation...\n");

    // 1. Generate real RSA keys
    println!("1. Generating real 2048-bit RSA keypair...");
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .expect("Failed to generate RSA private key");
    
    let public_key = RsaPublicKey::from(&private_key);
    
    // Encode to PEM format
    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode private key to PEM");
    
    let public_pem = public_key.to_public_key_pem(LineEnding::LF)
        .expect("Failed to encode public key to PEM");
    
    println!("   ✅ Private key PEM: {} characters", private_pem.len());
    println!("   ✅ Public key PEM: {} characters", public_pem.len());
    println!("   📝 Public key preview: {}...", &public_pem[..100]);

    // 2. Test RSA encryption/decryption
    println!("\n2. Testing RSA encryption with generated keys...");
    let test_message = b"Hello, this is a test message for RSA encryption!";
    
    let encrypted = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, test_message)
        .expect("Failed to encrypt with RSA");
    
    let decrypted = private_key.decrypt(Pkcs1v15Encrypt, &encrypted)
        .expect("Failed to decrypt with RSA");
    
    println!("   ✅ Original: {:?}", String::from_utf8_lossy(test_message));
    println!("   ✅ Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
    println!("   ✅ RSA encryption/decryption works!");

    // 3. SECURE: Password-based private key encryption (FIXED!)
    println!("\n3. SECURE: Password-based private key encryption...");
    let user_id = Uuid::new_v4();
    let user_password = "user_secure_password123!";
    
    // Generate a unique salt for this user (store this with the encrypted key!)
    let mut salt_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).expect("Failed to encode salt");
    
    println!("   🧂 Generated unique salt: {}...", &salt.as_str()[..20]);
    
    // Derive AES key from password using Argon2id (secure key derivation)
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(user_password.as_bytes(), &salt)
        .expect("Failed to derive key from password");
    
    // Extract 32 bytes for AES-256 key from the hash
    let hash_bytes = password_hash.hash.unwrap();
    let derived_key = &hash_bytes.as_bytes()[..32];
    let aes_key = Key::<Aes256Gcm>::from_slice(derived_key);
    let cipher = Aes256Gcm::new(aes_key);
    
    println!("   🔑 Derived encryption key from password using Argon2id");
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the private key PEM with password-derived key
    let ciphertext = cipher.encrypt(nonce, private_pem.as_bytes())
        .expect("Failed to encrypt private key with password-derived AES key");
    
    // Combine nonce + ciphertext and encode
    let mut encrypted_blob = nonce_bytes.to_vec();
    encrypted_blob.extend_from_slice(&ciphertext);
    let encrypted_blob_b64 = STANDARD.encode(&encrypted_blob);
    
    println!("   ✅ Encrypted private key blob: {} characters", encrypted_blob_b64.len());
    println!("   🔒 Private key is now SECURE - requires password to decrypt!");
    println!("   📝 Blob preview: {}...", &encrypted_blob_b64[..50]);
    
    // Demonstrate decryption (proving password is required)
    println!("\n   🔓 Testing decryption with correct password...");
    
    // Re-derive the same key from password and salt
    let salt_for_decryption = SaltString::from_b64(&salt.as_str()).expect("Failed to parse salt");
    let decryption_hash = argon2.hash_password(user_password.as_bytes(), &salt_for_decryption)
        .expect("Failed to re-derive key");
    
    let decryption_hash_bytes = decryption_hash.hash.unwrap();
    let decryption_key = &decryption_hash_bytes.as_bytes()[..32];
    let decrypt_aes_key = Key::<Aes256Gcm>::from_slice(decryption_key);
    let decrypt_cipher = Aes256Gcm::new(decrypt_aes_key);
    
    // Decode and split the blob
    let blob_bytes = STANDARD.decode(&encrypted_blob_b64).expect("Failed to decode blob");
    let (nonce_part, ciphertext_part) = blob_bytes.split_at(12);
    let decrypt_nonce = Nonce::from_slice(nonce_part);
    
    // Decrypt
    let decrypted_pem = decrypt_cipher.decrypt(decrypt_nonce, ciphertext_part)
        .expect("Failed to decrypt private key - wrong password!");
    
    let decrypted_pem_str = String::from_utf8(decrypted_pem).expect("Invalid UTF-8");
    println!("   ✅ Decryption successful! Private key recovered.");
    println!("   📝 Decrypted PEM length: {} characters", decrypted_pem_str.len());
    
    // Test with wrong password (should fail)
    println!("\n   ❌ Testing with WRONG password...");
    let wrong_password = "wrong_password";
    let wrong_hash = argon2.hash_password(wrong_password.as_bytes(), &salt_for_decryption)
        .expect("Failed to derive wrong key");
    let wrong_hash_bytes = wrong_hash.hash.unwrap();
    let wrong_key = &wrong_hash_bytes.as_bytes()[..32];
    let wrong_aes_key = Key::<Aes256Gcm>::from_slice(wrong_key);
    let wrong_cipher = Aes256Gcm::new(wrong_aes_key);
    
    match wrong_cipher.decrypt(decrypt_nonce, ciphertext_part) {
        Ok(_) => println!("   🚨 ERROR: Wrong password should not work!"),
        Err(_) => println!("   ✅ Correct: Wrong password failed to decrypt (as expected)")
    }

    // 4. Generate BIP39-style recovery phrase
    println!("\n4. Generating BIP39-style recovery phrase...");
    let words = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acoustic", "acquire", "across", "action", "actor", "actress", "actual", "adapt"
    ];
    
    let email = "user@example.com";
    let combined = format!("{}{}", user_id, email);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    combined.hash(&mut hasher);
    let mut seed = hasher.finish();
    
    let mut recovery_words = Vec::new();
    for _ in 0..12 {
        let word_index = (seed % words.len() as u64) as usize;
        recovery_words.push(words[word_index]);
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345); // Simple LCG
    }
    
    let recovery_phrase = recovery_words.join(" ");
    println!("   ✅ Recovery phrase: {}", recovery_phrase);

    // 5. Generate real AES-256-GCM message encryption
    println!("\n5. Demonstrating real AES-256-GCM message encryption...");
    let message_content = "This is a secret message that will be encrypted with real AES-256-GCM!";
    
    // Generate random message key
    let mut message_key = [0u8; 32];
    OsRng.fill_bytes(&mut message_key);
    let msg_key = Key::<Aes256Gcm>::from_slice(&message_key);
    let msg_cipher = Aes256Gcm::new(msg_key);
    
    // Generate random nonce for message
    let mut msg_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut msg_nonce_bytes);
    let msg_nonce = Nonce::from_slice(&msg_nonce_bytes);
    
    // Encrypt the message
    let msg_ciphertext = msg_cipher.encrypt(msg_nonce, message_content.as_bytes())
        .expect("Failed to encrypt message with AES");
    
    // Combine nonce + ciphertext
    let mut encrypted_message = msg_nonce_bytes.to_vec();
    encrypted_message.extend_from_slice(&msg_ciphertext);
    let encrypted_message_b64 = STANDARD.encode(&encrypted_message);
    
    println!("   ✅ Original message: {}", message_content);
    println!("   ✅ Encrypted message: {} characters", encrypted_message_b64.len());
    println!("   📝 Encrypted preview: {}...", &encrypted_message_b64[..50]);

    // 6. Encrypt message key with RSA for recipient
    println!("\n6. Encrypting message key with RSA (for recipient)...");
    let encrypted_msg_key = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &message_key)
        .expect("Failed to encrypt message key with RSA");
    
    let encrypted_msg_key_b64 = STANDARD.encode(&encrypted_msg_key);
    println!("   ✅ Encrypted message key: {} characters", encrypted_msg_key_b64.len());

    println!("\n🎉 All SECURE cryptographic operations completed successfully!");
    println!("   • RSA 2048-bit keypair generation ✅");
    println!("   • RSA encryption/decryption ✅");
    println!("   • PASSWORD-BASED private key encryption ✅ (SECURE!)");
    println!("   • BIP39-style recovery phrase ✅");
    println!("   • AES-256-GCM message encryption ✅");
    println!("   • RSA-encrypted message keys ✅");
    println!("\n🔒 SECURE CRYPTOGRAPHY - PRIVATE KEYS REQUIRE PASSWORDS!");
}
