#include "vg_crypto.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <iomanip>
#include <sstream>

#include "../vanguard_gateway.h"

using namespace std;

namespace vg_crypto {

vector<uint8_t> sha256(const uint8_t* data, size_t len) {
    if (!data && len > 0) return {};
    vector<uint8_t> buf(data, data + len);
    return VGW::Sha256(buf);
}

vector<uint8_t> sha256(const vector<uint8_t>& data) {
    return VGW::Sha256(data);
}

string sha256_hex(const uint8_t* data, size_t len) {
    auto hash = sha256(data, len);
    if (hash.empty()) return "";

    stringstream ss;
    for (uint8_t b : hash) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

string sha256_hex(const vector<uint8_t>& data) {
    return sha256_hex(data.data(), data.size());
}

vector<uint8_t> aes_gcm_encrypt(
    const uint8_t* key,
    const uint8_t* plain, size_t plain_len,
    const uint8_t* aad, size_t aad_len) {
    if (!key) return {};
    
    vector<uint8_t> key_vec(key, key + 32);
    vector<uint8_t> plain_vec(plain ? plain : (const uint8_t*)"", plain ? plain + plain_len : (const uint8_t*)"");
    vector<uint8_t> aad_vec(aad ? aad : (const uint8_t*)"", aad ? aad + aad_len : (const uint8_t*)"");
    
    auto res = VGW::AesGcmEncrypt(key_vec, plain_vec);
    
    vector<uint8_t> out;
    out.insert(out.end(), res.iv.begin(), res.iv.end());
    out.insert(out.end(), res.ciphertext.begin(), res.ciphertext.end());
    out.insert(out.end(), res.tag.begin(), res.tag.end());
    
    return out;
}

vector<uint8_t> aes_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* enc, size_t enc_len,
    const uint8_t* aad, size_t aad_len) {
    if (!key || !enc || enc_len < 28) return {};
    vector<uint8_t> key_vec(key, key + 32);
    vector<uint8_t> iv(enc, enc + 12);
    vector<uint8_t> ciphertext(enc + 12, enc + enc_len - 16);
    vector<uint8_t> tag(enc + enc_len - 16, enc + enc_len);
    return VGW::AesGcmDecrypt(key_vec, iv, ciphertext, tag);
}

vector<uint8_t> rsa_oaep_encrypt(
    const uint8_t* pub_der, size_t pub_len,
    const uint8_t* plain, size_t plain_len) {
    if (!pub_der || pub_len == 0 || !plain || plain_len == 0) return {};
    
    vector<uint8_t> der_vec(pub_der, pub_der + pub_len);
    vector<uint8_t> plain_vec(plain, plain + plain_len);
    
    auto hPubKey = VGW::ImportSpkiPublicKey(der_vec);
    if (!hPubKey) return {};
    auto rsa_enc_key = VGW::RsaOaepSha512Encrypt(hPubKey, plain_vec);
    BCryptDestroyKey(hPubKey);
    return rsa_enc_key;
}

} // namespace vg_crypto
