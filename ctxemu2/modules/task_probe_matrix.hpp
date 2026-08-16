#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>

static const int VG_TASK_RESULT = 9;

struct AtomicProbe {
    std::string key;
    std::string kind;
    int vg_type;
    std::vector<uint8_t> wire;
    int relay_flags;
    std::unordered_map<std::string, std::string> meta;
};

struct TaskTarget;

std::string payload_head_preview(const std::vector<uint8_t>& data, size_t n = 120);

std::vector<uint8_t> rg_encrypt_session(const std::vector<uint8_t>& plain,
    const std::vector<uint8_t>& session_aes,
    const std::vector<uint8_t>& server_rsa_pub);

std::vector<uint8_t> wrap_envelope(int type, const std::vector<uint8_t>& payload);

std::vector<uint8_t> build_task_wire_for_target(
    const std::string& access_token,
    const std::vector<uint8_t>& session_aes,
    const std::vector<uint8_t>& server_rsa_pub,
    const TaskTarget& target,
    const std::vector<uint8_t>& payload,
    const std::string& variant_name = "real_payload"
);

AtomicProbe build_single_task_probe(
    const std::string& access_token,
    const std::vector<uint8_t>& session_aes,
    const std::vector<uint8_t>& server_rsa_pub,
    const TaskTarget& target,
    const std::vector<uint8_t>& payload
);

std::vector<AtomicProbe> build_deterministic_task_probes(
    const std::string& access_token,
    const std::vector<uint8_t>& session_aes,
    const std::vector<uint8_t>& server_rsa_pub,
    const std::vector<TaskTarget>& targets,
    const std::vector<std::vector<uint8_t>>& payloads
);

struct ProbeQueueItem {
    std::string key;
    std::string kind;
    std::vector<uint8_t> wire;
    int vg_type = 0;
    int relay_flags = 0;
    std::string label;
    bool defer_wire = false;
    int defer_attempts = 0;
    std::string task_id;
    std::string cdn_path;
    std::string module_name;
    std::unordered_map<std::string, std::string> meta;
};

int enqueue_atomic_probes(
    std::vector<ProbeQueueItem>& pending,
    std::unordered_set<std::string>& seen,
    const std::vector<AtomicProbe>& probes,
    size_t max_queue,
    bool prepend = false
);
