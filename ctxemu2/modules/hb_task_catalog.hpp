#pragma once

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <filesystem>

#include "hb_parse.hpp"

namespace fs = std::filesystem;

struct TaskCatalogEntry {
    std::string task_id;
    std::string cdn_path;
    std::string cdn_mod_id;
    std::string module_name;
    std::string module_sha256_hex;
    int module_size = 0;
    std::optional<int> task_type;
    std::vector<uint8_t> template_json;
    std::string source;

    bool has_cdn() const { return !cdn_path.empty(); }
};

struct TaskCatalog {
    std::unordered_map<std::string, TaskCatalogEntry> entries;

    void merge(const TaskCatalog& other);

    std::vector<std::string> cdn_paths() const {
        std::vector<std::string> result;
        std::unordered_set<std::string> seen;
        for (const auto& [id, e] : entries) {
            if (!e.cdn_path.empty() && !seen.count(e.cdn_path)) {
                seen.insert(e.cdn_path);
                result.push_back(e.cdn_path);
            }
        }
        return result;
    }
};

bool is_valid_gateway_module_name(const std::string& name);

std::string mod_id_from_cdn(const std::string& path);
std::string sha256_hex_from_module_bytes(const std::vector<uint8_t>& raw);
int sanitize_module_size(int size, const std::string& mod_id = "");

TaskCatalog scan_binary_associations(const std::vector<uint8_t>& data);
TaskCatalog catalog_from_parsed(const HbParseResult& parsed);
TaskCatalog catalog_from_plain(const std::vector<uint8_t>& plain, int env_type = 8);
TaskCatalog catalog_from_paths(const std::vector<fs::path>& paths);
std::string catalog_to_json(const TaskCatalog& cat);
std::vector<fs::path> default_hb_search_dirs();
