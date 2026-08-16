

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "Crypt32.lib")

#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <chrono>


static const char VGW_RSA_PRIV_PEM[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"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\n"
"-----END RSA PRIVATE KEY-----\n";

static const char VGW_RIOT_PUBKEY_PEM[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxABI8XC5dAnqbJX6ZLWj\n"
"wiAPl18Pj/5q1E8I8raxRRJb7i7wmCuUEExKfwOBjbF4y4Wiugt8cloQniGqTzL7\n"
"JfvjpaZWYuM7OTd9YjACJRmm6CDjNsAxAA6PzH7B9LJd49Cp4ViHME65uUorsnQ6\n"
"riq0wbZSwNLaKWi9yoLlEX8Ru2CRgHJte35Fo1BcbB2S36SfwBu9tKMUbn1sAqjG\n"
"Mnzu8Slm9smtIoeugfvBEz4rpPpBH8n4/Nv89pZPf12O/64bHBfuK4v/g6Ig3T4M\n"
"T73MmXfxP4Hv3pI9+9ydnkzc3uZ+4LZbONVCyjJHcndeOcTzw2VIcJP5gVAxgaW\n"
"6WQIDAQAB\n"
"-----END PUBLIC KEY-----\n";

static const char VGW_CLIENT_PUBKEY[] =
"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArZ9KPHbgRlwgsJSDZKXN"
"ge4iG99WocrlS8Vy8tm9DlnnAcJZJGYWv1EFhr5ZgV43v4eyh/QI+czayvSuBckX"
"NbYuyMh1a8ML9nqZDalXhc06eCWINsDPCEfo+cW9Qewk2sq9gXqIaAyfRDlZEr5Z"
"0ScKxoE/Petd7kfp0OgaYc9NfoNOLLEeHjw58vppnLBEO8A82orcqzUtOj3Yltrf"
"bSI3oJrxhIwMR+DfCHY0RF11Pk6vNc4w6ePIaz/FBycZ3v+s+roBf56iujh01MOq"
"OfzCHwlK7pm+uuMvpFruNgkOJlga1Vui2JCukZ0LXdd3vjBoNvEsLsCTVm2akQdL"
"7auUQvwFfsNugx9iqBlvz8BVFovg7oyyUWKg7jPLMCZW3kq4kkZBGVEmJAXmooOT"
"LSuWS2M7CvO8X5YVwCNSqk5gsFmT9JqQ3VlY30zmF5BQwb/GtRF2hdMZrZUrQIKQ"  
"sIZvWqIQrWo7tpxxv9e5biInUohyqv1U5UFhmrRNmuof3axhpuD5OAQVF6RjpoUk"
"hIkjxkTBeeeSpvehLHsC+IZ7Jy5uUFglAI7aWWORYvliK2Ivhdy1BfyV3QA2nh4u"
"RQiKcp38W8IRzZJo6UApGdBzbx2OOIKQt0IJMWWHU+GuSz4d27lqt72nMFAk1yBe"
"6VWJsbcBW+I4xxj/ZKpbCQcCAwEAAQ==";

namespace VGW {

    static std::string Base64Encode(const uint8_t* data, size_t len) {
        DWORD outLen = 0;
        CryptBinaryToStringA(data, (DWORD)len,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen);
        std::string out(outLen, '\0');
        CryptBinaryToStringA(data, (DWORD)len,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen);
        while (!out.empty() && (out.back() == '\0' || out.back() == '\n' || out.back() == '\r'))
            out.pop_back();
        return out;
    }

    static std::vector<uint8_t> Base64Decode(const std::string& b64) {
        DWORD outLen = 0;
        CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
            CRYPT_STRING_BASE64_ANY, nullptr, &outLen, nullptr, nullptr);
        std::vector<uint8_t> out(outLen);
        CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
            CRYPT_STRING_BASE64_ANY, out.data(), &outLen, nullptr, nullptr);
        out.resize(outLen);
        return out;
    }

    static std::vector<uint8_t> PemToDer(const std::string& pem) {
        std::string b64;
        std::istringstream ss(pem);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty() || line[0] == '-') continue;
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            b64 += line;
        }
        return Base64Decode(b64);
    }

    static std::vector<uint8_t> RandomBytes(size_t n) {
        std::vector<uint8_t> buf(n);
        (void)BCryptGenRandom(nullptr, buf.data(), (ULONG)n,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        return buf;
    }

    static std::vector<uint8_t> Sha256(const std::vector<uint8_t>& data) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        BCRYPT_HASH_HANDLE hHash = nullptr;
        BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
        std::vector<uint8_t> hash(32);
        BCryptFinishHash(hHash, hash.data(), 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return hash;
    }


    static void pb_varint(std::vector<uint8_t>& buf, uint64_t val) {
        do {
            uint8_t b = val & 0x7F;
            val >>= 7;
            if (val) b |= 0x80;
            buf.push_back(b);
        } while (val);
    }

    static void pb_tag(std::vector<uint8_t>& buf, uint32_t field, uint8_t wire) {
        pb_varint(buf, ((uint64_t)field << 3) | wire);
    }

    static void pb_string(std::vector<uint8_t>& buf, uint32_t field, const std::string& s) {
        if (s.empty()) return;
        pb_tag(buf, field, 2);
        pb_varint(buf, s.size());
        buf.insert(buf.end(), s.begin(), s.end());
    }

    static void pb_int32(std::vector<uint8_t>& buf, uint32_t field, int32_t val) {
        if (val == 0) return;
        pb_tag(buf, field, 0);
        pb_varint(buf, (uint64_t)(int64_t)val);
    }

    static void pb_embedded(std::vector<uint8_t>& buf, uint32_t field, const std::vector<uint8_t>& inner) {
        if (inner.empty()) return;
        pb_tag(buf, field, 2);
        pb_varint(buf, inner.size());
        buf.insert(buf.end(), inner.begin(), inner.end());
    }

    static std::string GetFakeOsVersion() {
        static std::string cached;
        if (!cached.empty()) return cached;
        static const char* builds[] = {
            "10.0.19044",
            "10.0.19045",
            "10.0.22000",
            "10.0.22621",
            "10.0.22631",
            "10.0.26100",
        };
        uint8_t seed = 0;
        (void)BCryptGenRandom(nullptr, &seed, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        cached = builds[seed % (sizeof(builds) / sizeof(builds[0]))];
        return cached;
    }

    static std::vector<uint8_t> EncodeSubProto(int32_t f1, int32_t f2, const std::string& version, int32_t variant = 0) {
        std::vector<uint8_t> buf;
        pb_int32(buf, 1, f1);
        pb_int32(buf, 2, f2);
        if (variant != 0) pb_int32(buf, 3, variant);
        pb_string(buf, 4, version);
        return buf;
    }

    static std::vector<uint8_t> EncodeOSInfo(const std::string& version) {
        int build = 19045;
        auto pos = version.rfind('.');
        if (pos != std::string::npos) {
            try { build = std::stoi(version.substr(pos + 1)); }
            catch (...) {}
        }
        std::vector<uint8_t> buf;
        pb_int32(buf, 1, 1);
        pb_int32(buf, 2, build);
        pb_string(buf, 3, "Professional");
        pb_string(buf, 4, version);
        return buf;
    }

    static std::vector<uint8_t> EncodeMemoryInfo() {
        static uint64_t cached = 0;
        if (!cached) {
            static const uint64_t sizes[] = { 8589934592ULL, 17179869184ULL, 34359738368ULL };
            uint8_t seed = 0;
            (void)BCryptGenRandom(nullptr, &seed, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            cached = sizes[seed % 3];
        }
        std::vector<uint8_t> buf;
        pb_tag(buf, 1, 0);
        pb_varint(buf, cached);
        return buf;
    }

    static std::vector<uint8_t> EncodeCpuInfo(const std::string& brand, const std::string& model) {
        std::vector<uint8_t> buf;
        pb_string(buf, 1, brand);
        pb_string(buf, 2, model);
        return buf;
    }

    static std::vector<uint8_t> EncodeDeviceInfo(const std::string& os_version) {
        struct CpuEntry { const char* brand; const char* model; };
        static const CpuEntry cpus[] = {
            { "Intel", "Intel(R) Core(TM) i5-9400F CPU @ 2.90GHz"  },
            { "Intel", "Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz" },
            { "Intel", "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz" },
            { "Intel", "Intel(R) Core(TM) i5-11400F CPU @ 2.60GHz" },
            { "Intel", "Intel(R) Core(TM) i7-11700K CPU @ 3.60GHz" },
            { "Intel", "Intel(R) Core(TM) i5-12400F CPU @ 2.50GHz" },
            { "Intel", "Intel(R) Core(TM) i7-12700K CPU @ 3.60GHz" },
            { "AMD",   "AMD Ryzen 5 3600 6-Core Processor"          },
            { "AMD",   "AMD Ryzen 5 5600X 6-Core Processor"         },
            { "AMD",   "AMD Ryzen 7 5800X 8-Core Processor"         },
            { "AMD",   "AMD Ryzen 9 5900X 12-Core Processor"        },
            { "AMD",   "AMD Ryzen 5 7600X 6-Core Processor"         },
        };
        static int cpu_idx = -1;
        if (cpu_idx < 0) {
            uint8_t seed = 0;
            (void)BCryptGenRandom(nullptr, &seed, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            cpu_idx = seed % (int)(sizeof(cpus) / sizeof(cpus[0]));
        }

        std::vector<uint8_t> buf;
        pb_embedded(buf, 1, EncodeOSInfo(os_version));
        pb_embedded(buf, 2, EncodeMemoryInfo());
        pb_embedded(buf, 3, EncodeCpuInfo(cpus[cpu_idx].brand, cpus[cpu_idx].model));
        return buf;
    }

    static std::vector<uint8_t> EncodeAppInfo() {
        std::vector<uint8_t> buf;
        pb_int32(buf, 1, 2);
        pb_string(buf, 2, "1.18.5.11");
        return buf;
    }

    static std::vector<uint8_t> EncodeVgVersion(int32_t a, int32_t b, int32_t c, int32_t d) {
        std::vector<uint8_t> buf;
        pb_int32(buf, 1, a); pb_int32(buf, 2, b); pb_int32(buf, 3, c); pb_int32(buf, 4, d);
        return buf;
    }

    static std::vector<uint8_t> EncodeSecurityFeature(const std::string& name, int32_t state = 1) {
        std::vector<uint8_t> buf;
        pb_string(buf, 1, name);
        pb_int32(buf, 2, state);
        return buf;
    }

    static std::vector<uint8_t> EncodeMapEntry(const std::string& key, const std::string& val) {
        std::vector<uint8_t> buf;
        pb_string(buf, 1, key);
        pb_string(buf, 2, val);
        return buf;
    }


    static std::vector<uint8_t> EncodeGpuInfo(const std::string& brand, const std::string& model) {
        std::vector<uint8_t> buf;
        if (!brand.empty()) pb_string(buf, 1, brand);
        if (!model.empty()) pb_string(buf, 2, model);
        return buf;
    }


    static std::vector<uint8_t> EncodeOsInfo(const std::string& variant, const std::string& version) {
        std::vector<uint8_t> buf;
        pb_string(buf, 3, variant);
        pb_string(buf, 4, version);
        return buf;
    }


    static std::vector<uint8_t> EncodeCoreInfo(
        const std::string& cpu_brand, const std::string& cpu_model,
        const std::string& gpu_brand, const std::string& gpu_model,
        const std::string& os_variant, const std::string& os_version)
    {
        std::vector<uint8_t> buf;
        if (!cpu_brand.empty() || !cpu_model.empty())
            pb_embedded(buf, 1, EncodeCpuInfo(cpu_brand, cpu_model));
        if (!gpu_brand.empty() || !gpu_model.empty())
            pb_embedded(buf, 2, EncodeGpuInfo(gpu_brand, gpu_model));
        if (!os_variant.empty() || !os_version.empty())
            pb_embedded(buf, 3, EncodeOsInfo(os_variant, os_version));
        return buf;
    }


    // Field numbers from IDC scan:
    // - field 1: machine_id
    // - field 2: sub_proto
    // - field 4: game_token
    // - field 5: client_pubkey
    // - field 6: vg_version
    // - field 7: vg_version (duplicate)
    // - field 8: game_id
    // - field 9: boot_state
    // - field 10: ephemeral_id
    // - field 11: core_info
    // - field 12: boot_state (duplicate)
    // - field 13: external_sid
    // - field 14: security_features
    // - field 15: map_entry
    static std::vector<uint8_t> EncodeAuthRequest(
        const std::string& machine_id, const std::string& game_token,
        const std::string& external_sid, const std::string& game_id, int32_t boot_state,
        const std::string& client_pubkey = "", const std::string& ht_val = "",
        const std::string& ephemeral_id = "",
        const std::string& cpu_brand = "", const std::string& cpu_model = "",
        const std::string& gpu_brand = "", const std::string& gpu_model = "",
        const std::string& os_variant = "", const std::string& os_version = "")
    {
        std::vector<uint8_t> buf;
        pb_string(buf, 1, machine_id);                                      // field 1: machine_id
        pb_embedded(buf, 2, EncodeSubProto(1, 2, "10.0.19045"));           // field 2: sub_proto
        pb_string(buf, 4, game_token);                                      // field 4: game_token
        pb_string(buf, 5, client_pubkey.empty() ? std::string(VGW_CLIENT_PUBKEY) : client_pubkey); // field 5: client_pubkey
        auto vgver = EncodeVgVersion(1, 18, 5, 11);
        pb_embedded(buf, 6, vgver);                                         // field 6: vg_version
        pb_embedded(buf, 7, vgver);                                         // field 7: vg_version (duplicate)
        pb_string(buf, 8, game_id);                                         // field 8: game_id
        pb_int32(buf, 9, boot_state);                                       // field 9: boot_state
        if (!ephemeral_id.empty()) pb_string(buf, 10, ephemeral_id);        // field 10: ephemeral_id
        {
            std::vector<uint8_t> core;
            std::vector<uint8_t> cpu;
            pb_string(cpu, 1, cpu_brand);
            pb_string(cpu, 2, cpu_model);
            pb_embedded(core, 1, cpu);
            std::vector<uint8_t> gpu;
            if (!gpu_brand.empty()) pb_string(gpu, 1, gpu_brand);
            pb_string(gpu, 2, gpu_model);
            pb_embedded(core, 2, gpu);
            std::vector<uint8_t> osi;
            pb_int32(osi, 3, 1);
            pb_string(osi, 4, os_version.empty() ? std::string("10.0.19045") : os_version);
            pb_embedded(core, 3, osi);
            pb_embedded(buf, 11, core);                                     // field 11: core_info
        }
        pb_int32(buf, 12, boot_state);                                      // field 12: boot_state (duplicate)
        if (!external_sid.empty()) pb_string(buf, 13, external_sid);        // field 13: external_sid
        pb_embedded(buf, 14, EncodeSecurityFeature("HVCI", 1));             // field 14: security_features
        pb_embedded(buf, 14, EncodeSecurityFeature("IOMMU", 1));
        pb_embedded(buf, 14, EncodeSecurityFeature("SB", 1));
        pb_embedded(buf, 14, EncodeSecurityFeature("TPM2", 1));
        pb_embedded(buf, 14, EncodeSecurityFeature("VBS", 1));
        if (!ht_val.empty())
            pb_embedded(buf, 15, EncodeMapEntry("ht", ht_val));             // field 15: map_entry
        return buf;
    }

    static std::vector<uint8_t> EncodeAccessRequest(const std::string& token) {
        std::vector<uint8_t> buf;
        pb_string(buf, 1, token);
        return buf;
    }

    static std::vector<uint8_t> EncodeHeartbeatRequest(const std::string& token, const std::string& ephemeral_id = "") {
        using namespace std::chrono;
        uint64_t now_ms = (uint64_t)duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()).count();
        std::vector<uint8_t> buf;
        pb_string(buf, 1, token);
        pb_tag(buf, 2, 0); pb_varint(buf, now_ms);
        pb_int32(buf, 4, 1);
        pb_tag(buf, 6, 0); pb_varint(buf, 1);
        if (!ephemeral_id.empty()) pb_string(buf, 10, ephemeral_id);
        return buf;
    }

#ifndef GW_LOG
#define GW_LOG(fmt, ...) \
    do { char buf[512]; snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__); \
         OutputDebugStringA(buf); } while(0)
#endif

constexpr size_t MIN_VALID_PAYLOAD_SIZE = 32;

    // Response / Envelope headers from IDC scan:
    static const uint8_t AUTH_RESPONSE_HEADER[]   = { 0x08, 0x03, 0x12 }; // IDC scan: AUTH request/response header
    static const uint8_t ACCESS_RESPONSE_HEADER[] = { 0x08, 0x04, 0x12 }; // IDC scan: ACCESS request/response header
    static const uint8_t HEARTBEAT_RESPONSE_HEADER[] = { 0x08, 0x07, 0x12 }; // Heartbeat request/response header

    struct AuthResponse {
        std::string token, expiry, server_rsa_public_key, session_id;
        std::string ephemeral_identifiers;
        uint32_t unknown_id = 0, unknown_value = 0;
    };

    static bool ValidateGatewayResponse(const std::vector<uint8_t>& response) {
        if (response.size() < 20) {
            GW_LOG("[GW] Response too small: %zu bytes\n", response.size());
            return false;
        }
        if (response[0] != 0x08) {
            GW_LOG("[GW] Invalid response: wrong field type (0x%02X)\n", response[0]);
            return false;
        }
        if (response.size() > 8 && 
            (response[4] != 0x52 || response[5] != 0x47 || 
             response[6] != 0x01 || response[7] != 0x00)) {
            GW_LOG("[GW] Invalid response: wrong magic (0x%02X 0x%02X 0x%02X 0x%02X)\n",
                   response[4], response[5], response[6], response[7]);
            return false;
        }
        return true;
    }

    static std::string GenerateSessionContext(const std::string& jwt, const std::string& puuid, const std::string& region) {
        std::string combined = jwt + puuid + region;
        auto hash = Sha256(std::vector<uint8_t>(combined.begin(), combined.end()));
        return Base64Encode(hash.data(), hash.size());
    }

    static uint64_t pb_read_varint(const uint8_t* buf, size_t len, size_t& pos) {
        uint64_t val = 0; int shift = 0;
        while (pos < len) {
            uint8_t b = buf[pos++];
            val |= (uint64_t)(b & 0x7F) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        return val;
    }

    static AuthResponse DecodeAuthResponse(const std::vector<uint8_t>& data) {
        AuthResponse resp;
        size_t pos = 0;
        while (pos < data.size()) {
            uint64_t tag = pb_read_varint(data.data(), data.size(), pos);
            uint32_t field = (uint32_t)(tag >> 3);
            uint8_t  wire = (uint8_t)(tag & 0x7);
            if (wire == 0) {
                uint64_t val = pb_read_varint(data.data(), data.size(), pos);
                if (field == 3) resp.unknown_id = (uint32_t)val;
                if (field == 9) resp.unknown_value = (uint32_t)val;
            }
            else if (wire == 2) {
                uint64_t slen = pb_read_varint(data.data(), data.size(), pos);
                if (pos + slen > data.size()) break;
                std::string s((char*)data.data() + pos, (size_t)slen);
                pos += (size_t)slen;
                if (field == 1) resp.token = s;
                if (field == 2) resp.expiry = s;
                if (field == 4) resp.server_rsa_public_key = s;
                if (field == 8) resp.session_id = s;
                if (field == 10) resp.ephemeral_identifiers = s;
            }
            else { if (wire == 5) pos += 4; else if (wire == 1) pos += 8; else break; }
        }
        return resp;
    }

    struct AesGcmResult {
        std::vector<uint8_t> ciphertext, tag, iv;
    };

    static AesGcmResult AesGcmEncrypt(const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& plaintext)
    {
        AesGcmResult res;
        res.iv = RandomBytes(12);
        res.tag.resize(16);

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        (void)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        (void)BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        DWORD keyObjLen = 0, tmp = 0;
        (void)BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen, sizeof(DWORD), &tmp, 0);
        std::vector<uint8_t> keyObj(keyObjLen);
        (void)BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen,
            (PUCHAR)key.data(), (ULONG)key.size(), 0);
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = res.iv.data();
        authInfo.cbNonce = (ULONG)res.iv.size();
        authInfo.pbTag = res.tag.data();
        authInfo.cbTag = (ULONG)res.tag.size();
        authInfo.pbAuthData = nullptr;
        authInfo.cbAuthData = 0;
        DWORD cipherLen = 0;
        (void)BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
            &authInfo, nullptr, 0, nullptr, 0, &cipherLen, 0);
        res.ciphertext.resize(cipherLen);
        (void)BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
            &authInfo, nullptr, 0, res.ciphertext.data(), cipherLen, &cipherLen, 0);
        res.ciphertext.resize(cipherLen);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return res;
    }

    static std::vector<uint8_t> AesGcmDecrypt(
        const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag)
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        (void)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        (void)BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        DWORD keyObjLen = 0, tmp = 0;
        (void)BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen, sizeof(DWORD), &tmp, 0);
        std::vector<uint8_t> keyObj(keyObjLen);
        (void)BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen,
            (PUCHAR)key.data(), (ULONG)key.size(), 0);
        std::vector<uint8_t> tagCopy = tag;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)iv.data();
        authInfo.cbNonce = (ULONG)iv.size();
        authInfo.pbTag = tagCopy.data();
        authInfo.cbTag = (ULONG)tagCopy.size();
        authInfo.pbAuthData = nullptr;
        authInfo.cbAuthData = 0;
        DWORD plainLen = 0;
        (void)BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
            &authInfo, nullptr, 0, nullptr, 0, &plainLen, 0);
        std::vector<uint8_t> plain(plainLen);
        NTSTATUS st = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
            &authInfo, nullptr, 0, plain.data(), plainLen, &plainLen, 0);
        plain.resize(plainLen);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (st != 0) return {};
        return plain;
    }

    static BCRYPT_KEY_HANDLE ImportSpkiPublicKey(const std::vector<uint8_t>& spki_der) {
        CERT_PUBLIC_KEY_INFO* pkInfo = nullptr;
        DWORD pkInfoSize = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
            spki_der.data(), (DWORD)spki_der.size(),
            CRYPT_DECODE_ALLOC_FLAG, nullptr, &pkInfo, &pkInfoSize))
            return nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pkInfo, 0, nullptr, &hKey);
        LocalFree(pkInfo);
        return hKey;
    }

    static std::vector<uint8_t> RsaOaepSha512Encrypt(BCRYPT_KEY_HANDLE hKey,
        const std::vector<uint8_t>& plain)
    {
        BCRYPT_OAEP_PADDING_INFO pad{};
        pad.pszAlgId = BCRYPT_SHA512_ALGORITHM;
        pad.pbLabel = nullptr; pad.cbLabel = 0;
        DWORD cLen = 0;
        (void)BCryptEncrypt(hKey, (PUCHAR)plain.data(), (ULONG)plain.size(),
            &pad, nullptr, 0, nullptr, 0, &cLen, BCRYPT_PAD_OAEP);
        std::vector<uint8_t> c(cLen);
        (void)BCryptEncrypt(hKey, (PUCHAR)plain.data(), (ULONG)plain.size(),
            &pad, nullptr, 0, c.data(), cLen, &cLen, BCRYPT_PAD_OAEP);
        c.resize(cLen);
        return c;
    }

    static BCRYPT_KEY_HANDLE g_hPrivKey = nullptr;

    static BCRYPT_KEY_HANDLE LoadEmbeddedPrivateKey() {
        if (g_hPrivKey) return g_hPrivKey;
        auto der = PemToDer(VGW_RSA_PRIV_PEM);
        DWORD blobSize = (DWORD)der.size() * 2 + 128;
        std::vector<uint8_t> blob(blobSize);
        blobSize = (DWORD)blob.size();
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            PKCS_RSA_PRIVATE_KEY, der.data(), (DWORD)der.size(),
            0, nullptr, blob.data(), &blobSize))
            return nullptr;
        blob.resize(blobSize);
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        (void)BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        (void)BCryptImportKeyPair(hAlg, nullptr, LEGACY_RSAPRIVATE_BLOB,
            &g_hPrivKey, blob.data(), blobSize, 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return g_hPrivKey;
    }

    static BCRYPT_KEY_HANDLE g_hSessionPrivKey = nullptr;

    static std::vector<uint8_t> SpkiDerFromPublicBlob(const std::vector<uint8_t>& pubBlob) {
        auto* bh = (BCRYPT_RSAKEY_BLOB*)pubBlob.data();
        DWORD expLen = bh->cbPublicExp, modLen = bh->cbModulus;
        const uint8_t* expB = pubBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        const uint8_t* modB = expB + expLen;
        auto der_len = [](size_t n, std::vector<uint8_t>& v) {
            if (n < 0x80) v.push_back((uint8_t)n);
            else if (n < 0x100) { v.push_back(0x81); v.push_back((uint8_t)n); }
            else { v.push_back(0x82); v.push_back((uint8_t)(n >> 8)); v.push_back((uint8_t)n); }
            };
        auto der_int = [&](const uint8_t* d, size_t sz) {
            std::vector<uint8_t> r; r.push_back(0x02);
            size_t sk = 0; while (sk + 1 < sz && d[sk] == 0) sk++;
            bool pad = (d[sk] & 0x80) != 0;
            der_len(sz - sk + (pad ? 1 : 0), r);
            if (pad) r.push_back(0x00);
            r.insert(r.end(), d + sk, d + sz); return r;
            };
        auto mi = der_int(modB, modLen), ei = der_int(expB, expLen);
        std::vector<uint8_t> seq_body; seq_body.insert(seq_body.end(), mi.begin(), mi.end()); seq_body.insert(seq_body.end(), ei.begin(), ei.end());
        std::vector<uint8_t> seq; seq.push_back(0x30); der_len(seq_body.size(), seq); seq.insert(seq.end(), seq_body.begin(), seq_body.end());
        std::vector<uint8_t> bs; bs.push_back(0x03); der_len(seq.size() + 1, bs); bs.push_back(0x00); bs.insert(bs.end(), seq.begin(), seq.end());
        static const uint8_t oid[] = { 0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00 };
        std::vector<uint8_t> sb; sb.insert(sb.end(), oid, oid + sizeof(oid)); sb.insert(sb.end(), bs.begin(), bs.end());
        std::vector<uint8_t> spki; spki.push_back(0x30); der_len(sb.size(), spki); spki.insert(spki.end(), sb.begin(), sb.end());
        return spki;
    }

    static std::string g_cached_session_pubkey;

    static std::wstring GetRsaKeyPath() {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        wchar_t* last = wcsrchr(path, L'\\');
        if (last) *(last + 1) = L'\0';
        wcscat_s(path, L"rsa_key.bin");
        return path;
    }

    static bool SaveRsaKeyBlob(const std::vector<uint8_t>& privBlob) {
        auto path = GetRsaKeyPath();
        HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        uint32_t sz = (uint32_t)privBlob.size();
        WriteFile(hf, &sz, 4, &written, nullptr);
        WriteFile(hf, privBlob.data(), sz, &written, nullptr);
        CloseHandle(hf);
        return written == sz;
    }

    static std::vector<uint8_t> LoadRsaKeyBlob() {
        auto path = GetRsaKeyPath();
        HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return {};
        uint32_t sz = 0; DWORD rd = 0;
        ReadFile(hf, &sz, 4, &rd, nullptr);
        if (rd != 4 || sz == 0 || sz > 4096) { CloseHandle(hf); return {}; }
        std::vector<uint8_t> blob(sz);
        ReadFile(hf, blob.data(), sz, &rd, nullptr);
        CloseHandle(hf);
        return (rd == sz) ? blob : std::vector<uint8_t>{};
    }

    static bool ValidatePublicKeyFormat(const std::vector<uint8_t>& pubKeyBlob) {
        if (pubKeyBlob.empty()) return false;
        if (pubKeyBlob.size() >= sizeof(BCRYPT_RSAKEY_BLOB)) {
            const BCRYPT_RSAKEY_BLOB* header = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(pubKeyBlob.data());
            if (header->Magic == BCRYPT_RSAPUBLIC_MAGIC || header->Magic == BCRYPT_RSAFULLPRIVATE_MAGIC) {
                return true;
            }
        }
        if (pubKeyBlob[0] == 0x30 && pubKeyBlob.size() > 64) {
            return true;
        }
        return false;
    }

    static bool ValidatePublicKeyFormat(const std::string& pubKeyB64OrPem) {
        if (pubKeyB64OrPem.empty()) return false;
        if (pubKeyB64OrPem.find("-----BEGIN PUBLIC KEY-----") != std::string::npos || pubKeyB64OrPem.size() >= 60) {
            return true;
        }
        return false;
    }

    static std::string GenerateSessionClientKey() {

        if (g_hSessionPrivKey && !g_cached_session_pubkey.empty() && ValidatePublicKeyFormat(g_cached_session_pubkey))
            return g_cached_session_pubkey;

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0) != 0) return {};


        auto savedBlob = LoadRsaKeyBlob();
        if (!savedBlob.empty()) {
            if (BCryptImportKeyPair(hAlg, nullptr, BCRYPT_RSAPRIVATE_BLOB,
                &g_hSessionPrivKey, savedBlob.data(), (ULONG)savedBlob.size(), 0) == 0) {

                DWORD pubSz = 0;
                (void)BCryptExportKey(g_hSessionPrivKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &pubSz, 0);
                std::vector<uint8_t> pubBlob(pubSz);
                (void)BCryptExportKey(g_hSessionPrivKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, pubBlob.data(), pubSz, &pubSz, 0);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                if (ValidatePublicKeyFormat(pubBlob)) {
                    auto der = SpkiDerFromPublicBlob(pubBlob);
                    if (!der.empty()) {
                        std::string b64 = Base64Encode(der.data(), der.size());
                        if (ValidatePublicKeyFormat(b64)) {
                            g_cached_session_pubkey = b64;
                            return g_cached_session_pubkey;
                        }
                    }
                }
            }
        }


        if (g_hSessionPrivKey) { BCryptDestroyKey(g_hSessionPrivKey); g_hSessionPrivKey = nullptr; }
        // Generate key with standard size 3072-bit, fallback to 2048-bit if unsupported
        NTSTATUS keyStatus = BCryptGenerateKeyPair(hAlg, &g_hSessionPrivKey, 3072, 0);
        if (keyStatus != 0) {
            keyStatus = BCryptGenerateKeyPair(hAlg, &g_hSessionPrivKey, 2048, 0);
        }
        if (keyStatus != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return {}; }
        (void)BCryptFinalizeKeyPair(g_hSessionPrivKey, 0);


        DWORD privSz = 0;
        (void)BCryptExportKey(g_hSessionPrivKey, nullptr, BCRYPT_RSAPRIVATE_BLOB, nullptr, 0, &privSz, 0);
        std::vector<uint8_t> privBlob(privSz);
        if (BCryptExportKey(g_hSessionPrivKey, nullptr, BCRYPT_RSAPRIVATE_BLOB, privBlob.data(), privSz, &privSz, 0) == 0)
            SaveRsaKeyBlob(privBlob);

        DWORD pubSz = 0;
        (void)BCryptExportKey(g_hSessionPrivKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &pubSz, 0);
        std::vector<uint8_t> pubBlob(pubSz);
        (void)BCryptExportKey(g_hSessionPrivKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, pubBlob.data(), pubSz, &pubSz, 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (!ValidatePublicKeyFormat(pubBlob)) return {};

        auto der = SpkiDerFromPublicBlob(pubBlob);
        if (der.empty()) return {};
        std::string b64 = Base64Encode(der.data(), der.size());
        if (!ValidatePublicKeyFormat(b64)) return {};
        g_cached_session_pubkey = b64;
        return g_cached_session_pubkey;
    }

    static std::vector<uint8_t> RsaOaepSha512Decrypt(const std::vector<uint8_t>& cipher) {
        BCRYPT_KEY_HANDLE hKey = g_hSessionPrivKey ? g_hSessionPrivKey : LoadEmbeddedPrivateKey();
        if (!hKey) return {};
        BCRYPT_OAEP_PADDING_INFO pad{};
        pad.pszAlgId = BCRYPT_SHA512_ALGORITHM;
        pad.pbLabel = nullptr; pad.cbLabel = 0;
        DWORD pLen = 0;
        (void)BCryptDecrypt(hKey, (PUCHAR)cipher.data(), (ULONG)cipher.size(),
            &pad, nullptr, 0, nullptr, 0, &pLen, BCRYPT_PAD_OAEP);
        std::vector<uint8_t> plain(pLen);
        NTSTATUS st = BCryptDecrypt(hKey, (PUCHAR)cipher.data(), (ULONG)cipher.size(),
            &pad, nullptr, 0, plain.data(), pLen, &pLen, BCRYPT_PAD_OAEP);
        plain.resize(pLen);
        if (st != 0) return {};
        return plain;
    }

    static std::vector<uint8_t> RsaEncryptWithRetry(BCRYPT_KEY_HANDLE hKey,
        const std::vector<uint8_t>& plain, int max_retries = 3) {
        for (int attempt = 0; attempt < max_retries; attempt++) {
            auto result = RsaOaepSha512Encrypt(hKey, plain);
            if (!result.empty()) return result;
            if (attempt < max_retries - 1) {
                GW_LOG("[GW] RSA encrypt retry attempt %d\n", attempt + 1);
                Sleep(100 * (1 << attempt));
            }
        }
        return {};
    }

    static std::vector<uint8_t> BuildPayload(
        const std::vector<uint8_t>& proto_data,
        const std::vector<uint8_t>& pubkey_der,
        uint8_t type_byte)
    {
        auto aes_key = RandomBytes(32);
        auto gcm = AesGcmEncrypt(aes_key, proto_data);

        auto hPubKey = ImportSpkiPublicKey(pubkey_der);
        if (!hPubKey) return {};
        auto rsa_enc_key = RsaEncryptWithRetry(hPubKey, aes_key);
        BCryptDestroyKey(hPubKey);
        if (rsa_enc_key.size() != 256 && rsa_enc_key.size() != 384) return {};

        std::vector<uint8_t> rito;
        const uint8_t magic[] = { 0x52, 0x47, 0x01, 0x00 };
        rito.insert(rito.end(), magic, magic + 4);
        rito.insert(rito.end(), rsa_enc_key.begin(), rsa_enc_key.end());
        rito.insert(rito.end(), gcm.iv.begin(), gcm.iv.end());
        rito.insert(rito.end(), gcm.ciphertext.begin(), gcm.ciphertext.end());
        rito.insert(rito.end(), gcm.tag.begin(), gcm.tag.end());

        std::vector<uint8_t> env;

        // field 1: type (varint)
        env.push_back(0x08);  // field 1, wire type 0
        pb_varint(env, type_byte);

        // field 2: payload (bytes)
        env.push_back(0x12);  // field 2, wire type 2
        pb_varint(env, rito.size());
        env.insert(env.end(), rito.begin(), rito.end());

        return env;
    }

    static std::vector<uint8_t> DecryptGatewayResponse(const std::vector<uint8_t>& payload) {
        if (payload.size() < MIN_VALID_PAYLOAD_SIZE) {
            GW_LOG("[GW] Payload too small for decryption: %zu bytes < %zu\n", payload.size(), MIN_VALID_PAYLOAD_SIZE);
            return {};
        }
        if (!ValidateGatewayResponse(payload)) {
            GW_LOG("[GW] DecryptGatewayResponse rejected invalid response structure\n");
            return {};
        }
        size_t pos = 0;
        if (pos >= payload.size() || payload[pos++] != 0x08) return {};
        if (pos >= payload.size()) return {};
        uint8_t type = payload[pos++];
        if (type != 0x03 && type != 0x04 && type != 0x07 && type != 0x09) {
            GW_LOG("[GW] DecryptGatewayResponse rejected invalid response type: 0x%02X\n", type);
            return {};
        }
        if (pos >= payload.size() || payload[pos++] != 0x12) return {};


        uint64_t len = pb_read_varint(payload.data(), payload.size(), pos);
        if (pos + len > payload.size()) return {};


        if (pos + 4 > payload.size()) return {};
        if (payload[pos] != 0x52 || payload[pos + 1] != 0x47 || payload[pos + 2] != 0x01 || payload[pos + 3] != 0x00) {
            return {};
        }
        pos += 4;

        size_t rsa_key_len = 256;
        if (pos + 384 + 12 + 16 <= payload.size() && len >= 4 + 384 + 12 + 16) {
            rsa_key_len = 384;
        }
        if (pos + rsa_key_len + 12 + 16 > payload.size()) return {};

        std::vector<uint8_t> enc_key(payload.begin() + pos, payload.begin() + pos + rsa_key_len);
        pos += rsa_key_len;
        std::vector<uint8_t> iv(payload.begin() + pos, payload.begin() + pos + 12);
        pos += 12;

        size_t cipher_len = payload.size() - pos - 16;
        std::vector<uint8_t> cipher(payload.begin() + pos, payload.begin() + pos + cipher_len);
        pos += cipher_len;

        std::vector<uint8_t> tag(payload.begin() + pos, payload.begin() + pos + 16);

        auto aes_key = RsaOaepSha512Decrypt(enc_key);
        if (aes_key.size() != 32) return {};
        return AesGcmDecrypt(aes_key, iv, cipher, tag);
    }


    static std::vector<uint8_t> GetRiotPubkeyDer() {
        return PemToDer(VGW_RIOT_PUBKEY_PEM);
    }

    static std::vector<uint8_t> BuildGatewayAuthPayload(
        const std::string& game_token,
        const std::string& external_sid,
        const std::string& machine_id = "",
        const std::string& ht_override = "",
        const std::string& ephemeral_id = "",
        const std::string& cpu_brand = "",
        const std::string& cpu_model = "",
        const std::string& gpu_brand = "",
        const std::string& gpu_model = "",
        const std::string& os_variant = "Windows 10 Pro",
        const std::string& os_version = "10.0.19045",
        int32_t boot_state = 3)
    {
        std::string client_pubkey = VGW_CLIENT_PUBKEY;
        std::string ht_val;
        if (!ht_override.empty()) {
            ht_val = ht_override;
        }
        else if (!machine_id.empty()) {
            std::vector<uint8_t> mid_bytes(machine_id.begin(), machine_id.end());
            auto hashed = Sha256(mid_bytes);
            ht_val = Base64Encode(hashed.data(), 20);
        }

        auto proto = EncodeAuthRequest(
            machine_id, game_token, external_sid,
            "com.riotgames.valorant", boot_state, client_pubkey, ht_val,
            ephemeral_id, cpu_brand, cpu_model, gpu_brand, gpu_model, os_variant, os_version);


        {
            std::string hex_dump = "[GW-PROTO] Auth proto hex (" + std::to_string(proto.size()) + "B): ";
            for (auto b : proto) {
                char buf[3]; snprintf(buf, sizeof(buf), "%02X", b);
                hex_dump += buf;
            }
            GW_LOG("%s\n", hex_dump.c_str());

            HANDLE hf = CreateFileA("C:\\proto_dump.bin", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
            if (hf != INVALID_HANDLE_VALUE) {
                DWORD w = 0;
                WriteFile(hf, proto.data(), (DWORD)proto.size(), &w, nullptr);
                CloseHandle(hf);
            }
        }

        return BuildPayload(proto, GetRiotPubkeyDer(), 0x03);
    }

    static std::vector<uint8_t> BuildGatewayAccessPayload(
        const std::vector<uint8_t>& gateway_auth_response,
        std::string& out_server_pubkey,
        std::string& out_token,
        std::string* out_ephemeral_id = nullptr)
    {
        auto decrypted = DecryptGatewayResponse(gateway_auth_response);
        if (decrypted.empty()) return {};
        auto resp = DecodeAuthResponse(decrypted);
        out_server_pubkey = resp.server_rsa_public_key;
        out_token = resp.token;
        if (out_ephemeral_id) *out_ephemeral_id = resp.ephemeral_identifiers;
        if (resp.server_rsa_public_key.empty()) return {};

        std::vector<uint8_t> server_pub_der;
        if (resp.server_rsa_public_key.find("-----BEGIN") != std::string::npos)
            server_pub_der = PemToDer(resp.server_rsa_public_key);
        else
            server_pub_der = Base64Decode(resp.server_rsa_public_key);

        auto accessProto = EncodeAccessRequest(resp.token);
        return BuildPayload(accessProto, server_pub_der, 0x04);
    }

    static std::vector<uint8_t> BuildGatewayHeartbeatPayload(
        const std::vector<uint8_t>& prev_auth_response,
        std::string& out_server_pubkey,
        std::string* out_ephemeral_id = nullptr)
    {
        auto decrypted = DecryptGatewayResponse(prev_auth_response);
        if (decrypted.empty()) return {};
        auto resp = DecodeAuthResponse(decrypted);
        out_server_pubkey = resp.server_rsa_public_key;
        if (out_ephemeral_id) *out_ephemeral_id = resp.ephemeral_identifiers;
        if (resp.server_rsa_public_key.empty()) return {};

        std::vector<uint8_t> server_pub_der;
        if (resp.server_rsa_public_key.find("-----BEGIN") != std::string::npos)
            server_pub_der = PemToDer(resp.server_rsa_public_key);
        else
            server_pub_der = Base64Decode(resp.server_rsa_public_key);

        std::string eph_id;
        if (out_ephemeral_id && !out_ephemeral_id->empty()) eph_id = *out_ephemeral_id;
        else eph_id = resp.ephemeral_identifiers;
        if (out_ephemeral_id) *out_ephemeral_id = resp.ephemeral_identifiers;

        auto hbProto = EncodeHeartbeatRequest(resp.token, eph_id);
        return BuildPayload(hbProto, server_pub_der, 0x07);
    }

    struct GatewaySession {
        std::vector<uint8_t> last_auth_response;
        std::string          server_public_key;
        std::string          token;
        std::string          ephemeral_identifiers;
        std::string          session_context_hash;
        bool                 ready = false;
        double               cached_at = 0.0;
        bool                 gw_posted = false;
        int                  keepalive_countdown = 0;

        void Reset() {
            last_auth_response.clear();
            server_public_key.clear();
            token.clear();
            ephemeral_identifiers.clear();
            session_context_hash.clear();
            ready = false;
            cached_at = 0.0;
            gw_posted = false;
            keepalive_countdown = 0;
        }
    };

}
