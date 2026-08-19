#include "task_probe_matrix.hpp"
#include "task_result_variants.hpp"
#include "vg_crypto.hpp"
#include <cstring>

using namespace std;

static const int FLAG_PROBE_FORCE_XVG0 = 0x100;

string payload_head_preview(const vector<uint8_t>& data, size_t n) {
    if (data.empty()) return "";
    size_t len = min(n, data.size());
    string text(reinterpret_cast<const char*>(data.data()), len);
    string result;
    for (char c : text) {
        if ((c >= 32 && c < 127) && c != '\r' && c != '\n') result += c;
        else result += '.';
    }
    return result;
}

vector<uint8_t> rg_encrypt_session(const vector<uint8_t>& plain,
    const vector<uint8_t>& session_aes,
    const vector<uint8_t>& server_rsa_pub) {
    
    if (session_aes.size() != 32 || server_rsa_pub.empty()) return plain;

    // 1. AES-256-GCM ile payload şifrele
    auto encrypted = vg_crypto::aes_gcm_encrypt(
        session_aes.data(), plain.data(), plain.size());
    if (encrypted.empty()) return {};  // Hata → probe iptal (plain fallback DEĞİL)

    // 2. AES key'i RSA-OAEP ile şifrele
    auto encrypted_key = vg_crypto::rsa_oaep_encrypt(
        server_rsa_pub.data(), server_rsa_pub.size(),
        session_aes.data(), session_aes.size());
    if (encrypted_key.empty()) return {};  // Hata → probe iptal

    // 3. Wire format: [4-byte key_len LE][encrypted_key][encrypted_payload]
    //    encrypted_payload = [12-byte nonce][ciphertext][16-byte tag]
    uint32_t key_len = static_cast<uint32_t>(encrypted_key.size());
    vector<uint8_t> out;
    out.reserve(4 + encrypted_key.size() + encrypted.size());
    
    out.push_back(static_cast<uint8_t>(key_len & 0xFF));
    out.push_back(static_cast<uint8_t>((key_len >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((key_len >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((key_len >> 24) & 0xFF));
    
    out.insert(out.end(), encrypted_key.begin(), encrypted_key.end());
    out.insert(out.end(), encrypted.begin(), encrypted.end());
    
    return out;
}

vector<uint8_t> wrap_envelope(int type, const vector<uint8_t>& payload) {
    vector<uint8_t> out;
    uint64_t key = (static_cast<uint64_t>(type) << 3) | 2;
    while (key >= 0x80) {
        out.push_back(static_cast<uint8_t>((key & 0x7F) | 0x80));
        key >>= 7;
    }
    out.push_back(static_cast<uint8_t>(key));

    uint64_t len = payload.size();
    while (len >= 0x80) {
        out.push_back(static_cast<uint8_t>((len & 0x7F) | 0x80));
        len >>= 7;
    }
    out.push_back(static_cast<uint8_t>(len));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

vector<uint8_t> build_task_wire_for_target(
    const string& access_token,
    const vector<uint8_t>& session_aes,
    const vector<uint8_t>& server_rsa_pub,
    const TaskTarget& target,
    const vector<uint8_t>& payload,
    const string& variant_name
) {
    TaskResultVariant variant;
    variant.name = variant_name;
    variant.data = payload;
    variant.field_order = {1, 2, 3};
    variant.status = 1;
    variant.id_wire = "string";

    auto sub = encode_task_result_submessage(variant, target);
    auto plain = encode_task_result_request(access_token, {sub});
    auto rg = rg_encrypt_session(plain, session_aes, server_rsa_pub);
    return wrap_envelope(VG_TASK_RESULT, rg);
}

AtomicProbe build_single_task_probe(
    const string& access_token,
    const vector<uint8_t>& session_aes,
    const vector<uint8_t>& server_rsa_pub,
    const TaskTarget& target,
    const vector<uint8_t>& payload
) {
    string tid = !target.id_str.empty() ? target.id_str :
        (target.id_uint.has_value() ? to_string(target.id_uint.value()) : "");

    auto wire = build_task_wire_for_target(access_token, session_aes, server_rsa_pub, target, payload);
    string key = "task:" + tid.substr(0, 24) + ":real:xvg1=9";

    AtomicProbe probe;
    probe.key = key;
    probe.kind = "task";
    probe.vg_type = VG_TASK_RESULT;
    probe.wire = wire;
    probe.relay_flags = 0;
    probe.meta["target"] = target.label;
    probe.meta["variant"] = "real_payload";
    probe.meta["hdr"] = "xvg1_9";
    probe.meta["xvg1"] = to_string(VG_TASK_RESULT);
    probe.meta["task_id"] = tid;
    probe.meta["payload_len"] = to_string(payload.size());
    probe.meta["payload_head"] = payload_head_preview(payload, 120);

    return probe;
}

vector<AtomicProbe> build_deterministic_task_probes(
    const string& access_token,
    const vector<uint8_t>& session_aes,
    const vector<uint8_t>& server_rsa_pub,
    const vector<TaskTarget>& targets,
    const vector<vector<uint8_t>>& payloads
) {
    vector<AtomicProbe> probes;
    for (size_t i = 0; i < targets.size(); i++) {
        if (i >= payloads.size() || payloads[i].empty()) continue;
        probes.push_back(build_single_task_probe(access_token, session_aes, server_rsa_pub, targets[i], payloads[i]));
    }
    return probes;
}

int enqueue_atomic_probes(
    vector<ProbeQueueItem>& pending,
    unordered_set<string>& seen,
    const vector<AtomicProbe>& probes,
    size_t max_queue,
    bool prepend
) {
    int added = 0;
    for (const auto& p : probes) {
        if (seen.count(p.key)) continue;

        int wire_count = 0;
        for (const auto& x : pending) {
            if (!x.defer_wire) wire_count++;
        }
        if (static_cast<size_t>(wire_count) >= max_queue) break;

        seen.insert(p.key);
        ProbeQueueItem item;
        item.key = p.key;
        item.kind = p.kind;
        item.wire = p.wire;
        item.vg_type = p.vg_type;
        item.relay_flags = p.relay_flags;
        item.label = p.key;
        item.meta = p.meta;

        if (prepend) pending.insert(pending.begin(), item);
        else pending.push_back(item);
        added++;
    }
    return added;
}
