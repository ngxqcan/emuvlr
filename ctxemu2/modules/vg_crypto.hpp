#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vg_crypto {

// ── SHA-256 ──────────────────────────────────────────────────────────
// Compute SHA-256 digest, returns 32-byte vector (empty on error).
std::vector<uint8_t> sha256(const uint8_t* data, size_t len);
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

// Hex-encoded SHA-256 digest (64-char lowercase string, empty on error).
std::string sha256_hex(const uint8_t* data, size_t len);
std::string sha256_hex(const std::vector<uint8_t>& data);

// ── AES-256-GCM ─────────────────────────────────────────────────────
// Encrypt with AES-256-GCM.
// key: 32 bytes.  Nonce is randomly generated (12 bytes).
// Output format: [12-byte nonce][ciphertext][16-byte tag]
// Returns empty vector on error.
std::vector<uint8_t> aes_gcm_encrypt(
    const uint8_t* key,
    const uint8_t* plain, size_t plain_len,
    const uint8_t* aad = nullptr, size_t aad_len = 0);

// Decrypt AES-256-GCM.
// key: 32 bytes.
// Input format: [12-byte nonce][ciphertext][16-byte tag]
// Returns empty vector on error (including auth failure).
std::vector<uint8_t> aes_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* enc, size_t enc_len,
    const uint8_t* aad = nullptr, size_t aad_len = 0);

// ── RSA-OAEP ────────────────────────────────────────────────────────
// Encrypt with RSA-2048 OAEP (SHA-256 hash, MGF1-SHA-256).
// pub_der: DER-encoded SubjectPublicKeyInfo.
// Returns empty vector on error.
std::vector<uint8_t> rsa_oaep_encrypt(
    const uint8_t* pub_der, size_t pub_len,
    const uint8_t* plain, size_t plain_len);

} // namespace vg_crypto
