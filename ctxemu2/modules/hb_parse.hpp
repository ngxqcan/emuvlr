#pragma once

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <optional>
#include <regex>
#include <filesystem>

namespace fs = std::filesystem;

static const int VG_MODULES_RESP = 6;

struct ModuleBlob {
    std::string mod_id;
    std::string cdn_path;
    std::string url;
    std::vector<uint8_t> data;
    std::string sha256_hex;
    fs::path cache_path;
};

struct ModuleRecord {
    std::string module_id;
    std::string cdn_url;
    std::vector<std::string> arguments;
    std::vector<uint8_t> sha256;
    int size = 0;
    int load_flags = 0;
};

struct ModuleTaskData {
    std::string id_str;
    std::string cdn_url;
    std::optional<ModuleRecord> module;
    std::optional<int> task_type;
    std::optional<int> aux_type;
    std::vector<uint8_t> extra_raw;
};

struct TaskRecord {
    std::optional<uint64_t> id_uint;
    std::optional<ModuleTaskData> module_task;
};

struct HbParseResult {
    int env_type = 0;
    uint64_t timestamp = 0;
    bool should_disconnect = false;
    std::vector<TaskRecord> tasks;
    std::vector<std::string> active_task_strings;
    std::vector<ModuleRecord> modules;
    std::vector<std::string> cdn_urls;
    std::vector<std::string> all_strings;
    int plain_bytes = 0;
    int slice_bytes = 0;
    int slice_offset = 0;
    std::string field_summary;
};

struct TargetEntry {
    std::string kind;
    std::unordered_map<std::string, std::string> attrs;
};

uint64_t read_varint(const std::vector<uint8_t>& data, size_t& pos);
std::pair<uint64_t, size_t> read_varint_pair(const std::vector<uint8_t>& data, size_t pos);

std::string sanitize_cdn_path(const std::string& raw);

bool looks_like_module_name(const std::string& s);
bool looks_like_vanguard_task_id_hex(const std::string& s);
bool looks_like_task_id_string(const std::string& s);
bool looks_like_hb_response_root(const std::vector<uint8_t>& data);
bool is_mostly_printable(const std::vector<uint8_t>& data);
bool looks_like_url(const std::string& s);
bool looks_like_unix_ms(uint64_t ts);
bool looks_like_base64_blob(const std::string& s);

int strict_hb_response_score(const std::vector<uint8_t>& data);
std::pair<std::vector<uint8_t>, int> find_heartbeat_protobuf_slice(const std::vector<uint8_t>& plain);
std::string summarize_protobuf_fields(const std::vector<uint8_t>& data, int max_fields = 16);

ModuleRecord parse_module_submessage(const std::vector<uint8_t>& data);
ModuleTaskData parse_module_task_data(const std::vector<uint8_t>& data);
std::optional<uint64_t> read_task_root_varint_id(const std::vector<uint8_t>& data);
TaskRecord parse_task_submessage(const std::vector<uint8_t>& data);

HbParseResult parse_hb_plain(const std::vector<uint8_t>& plain, int env_type = 8);
void collect_tasks_from_modules_response(const std::vector<uint8_t>& data, HbParseResult& out, std::unordered_set<std::string>& seen);
void extract_nested_task_strings(const std::vector<uint8_t>& data, HbParseResult& out, int depth = 0);
void deep_collect_tasks(const std::vector<uint8_t>& data, HbParseResult& out, std::unordered_set<std::string>& seen, int depth = 0);
void parse_hb_field2_chunk(const std::vector<uint8_t>& data, HbParseResult& out, std::unordered_set<std::string>& seen);
void scan_urls_in_blob(HbParseResult& out, const std::vector<uint8_t>& data);

std::vector<TargetEntry> collect_task_targets(const HbParseResult& parsed);
std::vector<TargetEntry> collect_real_task_targets(const HbParseResult& parsed);

std::string format_parse_report(const HbParseResult& parsed);
std::string hex_preview(const std::vector<uint8_t>& data, int max_bytes = 64);

std::string resolve_cdn_url(const std::string& path, const std::string& region);
ModuleBlob download_module(const std::string& cdn_path, const std::string& region, const std::string& cookies);
