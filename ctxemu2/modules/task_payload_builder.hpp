#pragma once

#include <cstdint>
#include <ctime>
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <filesystem>

#include "hb_parse.hpp"
#include "hb_task_catalog.hpp"

class TaskPayloadCache {
public:
    void set_gw_cookies(const std::string& cookies) { gw_cookies = cookies; }

    void mark_pc_fetched(const std::string& cdn_path) {
        if (cdn_path.empty()) return;
        pc_fetched.insert(cdn_path);
        std::string mod = mod_id_from_path(cdn_path);
        if (!mod.empty()) pc_fetched_mods.insert(mod);
        fail_until.erase(cdn_path);
    }

    bool has_pc_fetched_mod(const std::string& mod_id) const {
        return !mod_id.empty() && pc_fetched_mods.count(mod_id) > 0;
    }

    bool has_module(const std::string& cdn_path, const std::string& region = "la") const {
        std::string clean = sanitize_cdn_path(cdn_path);
        if (clean.empty()) return false;
        std::string mod = mod_id_from_path(clean);
        if (!mod.empty() && pc_fetched_mods.count(mod)) return true;
        if (pc_fetched.count(clean)) return true;
        if (blobs.count(clean)) return true;

        std::string mod_id = clean;
        size_t pos = clean.find("/v1/cdn/mod/");
        if (pos != std::string::npos) {
            mod_id = clean.substr(pos + 13);
            size_t q = mod_id.find('?');
            if (q != std::string::npos) mod_id = mod_id.substr(0, q);
        }
        fs::path p = fs::current_path().parent_path().parent_path() / "logs" / "modules_cache" / (mod_id + ".bin");
        return fs::exists(p) && fs::file_size(p) > 0;
    }

    void ingest_blob(const std::string& cdn_path, const std::vector<uint8_t>& data, const std::string& region = "la") {
        std::string clean = sanitize_cdn_path(cdn_path);
        if (clean.empty() || data.empty()) return;

        std::string mod_id = clean;
        size_t pos = clean.find("/v1/cdn/mod/");
        if (pos != std::string::npos) {
            mod_id = clean.substr(pos + 13);
            size_t q = mod_id.find('?');
            if (q != std::string::npos) mod_id = mod_id.substr(0, q);
        }

        fs::path cache_root = fs::current_path().parent_path().parent_path() / "logs" / "modules_cache";
        fs::create_directories(cache_root);
        fs::path cache_path = cache_root / (mod_id + ".bin");
        FILE* f = fopen(cache_path.string().c_str(), "wb");
        if (f) {
            fwrite(data.data(), 1, data.size(), f);
            fclose(f);
        }

        ModuleBlob blob;
        blob.mod_id = mod_id;
        blob.cdn_path = clean;
        blob.url = resolve_cdn_url(clean, region);
        blob.data = data;
        blob.cache_path = cache_path;

        blobs[clean] = std::move(blob);
        fail_until.erase(clean);
    }

    std::optional<ModuleBlob> get_module(const std::string& cdn_path, const std::string& region = "la", bool allow_download = false) {
        std::string clean = sanitize_cdn_path(cdn_path);
        if (clean.empty()) return std::nullopt;
        if (blobs.count(clean)) return blobs[clean];
        if (pc_fetched.count(clean)) return std::nullopt;
        if (!allow_download) return std::nullopt;

        double now = static_cast<double>(std::time(nullptr));
        auto it = fail_until.find(clean);
        if (it != fail_until.end() && now < it->second) return std::nullopt;

        ModuleBlob blob = download_module(clean, region, gw_cookies);
        if (!blob.mod_id.empty()) {
            blobs[clean] = blob;
            return blob;
        }
        fail_until[clean] = now + 120.0;
        return std::nullopt;
    }

    bool has_mod(const std::string& cdn_path, const std::string& region) const {
        return has_module(cdn_path, region);
    }

private:
    static std::string mod_id_from_path(const std::string& cdn_path) {
        size_t pos = cdn_path.find("/v1/cdn/mod/");
        if (pos == std::string::npos) return "";
        std::string rest = cdn_path.substr(pos + 13);
        size_t q = rest.find('?');
        if (q != std::string::npos) rest = rest.substr(0, q);
        return rest;
    }

    std::unordered_map<std::string, ModuleBlob> blobs;
    std::unordered_set<std::string> pc_fetched;
    std::unordered_set<std::string> pc_fetched_mods;
    std::unordered_map<std::string, double> fail_until;
    std::string gw_cookies;
};

std::string build_mc_sentinel_json();
std::string build_module_result_json();
std::string build_npt_survey_json();
std::string build_pc_task_json();
std::vector<uint8_t> encode_task_performance_submessage(uint64_t duration_ns);

bool is_valid_gateway_module_name(const std::string& name);
std::string module_name_for_task(TaskPayloadCache& queue, const TaskCatalog& catalog, const std::string& task_id);
std::string module_name_for_mod_id(TaskPayloadCache& queue, const TaskCatalog& catalog, const std::string& mod_id);

std::vector<uint8_t> build_task_payload(
    const std::string& task_id,
    const TaskCatalog& catalog,
    TaskPayloadCache& cache,
    const std::string& region = "la",
    const std::string& gw_cookies = ""
);

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> build_task_payload_with_perf(
    const std::string& task_id,
    const TaskCatalog& catalog,
    TaskPayloadCache& cache,
    const std::string& region = "la"
);
