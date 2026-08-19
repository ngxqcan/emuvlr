#include "hb_task_catalog.hpp"
#include <cstring>
#include <algorithm>
#include <regex>
#include <cstdio>

using namespace std;

static const regex TASK_ID_RE("(?:6a49|6a4a)[0-9a-f]{20}", regex_constants::icase);
static const regex CDN_PATH_RE("/v1/cdn/mod/\\d+\\?verify=[0-9A-Za-z%\\-\\._\\+/=]+", regex_constants::icase);
static const vector<uint8_t> JSON_EXCLUDE_MARK = {'{','"','e','x','c','l','u','d','e','"',':'};

bool is_valid_gateway_module_name(const string& name) {
    if (name.size() < 32 || name.size() > 512) return false;
    if (name[0] == '{' || name[0] == '[') return false;
    if (name.find("/v1/cdn/") != string::npos) return false;
    if (name.find("://") != string::npos) return false;
    return true;
}

string mod_id_from_cdn(const string& path) {
    regex re("/v1/cdn/mod/(\\d+)");
    smatch m;
    if (regex_search(path, m, re) && m.size() > 1) return m.str(1);
    return "";
}

string sha256_hex_from_module_bytes(const vector<uint8_t>& raw) {
    if (raw.empty()) return "";
    string result;
    for (uint8_t b : raw) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        result += buf;
    }
    if (raw.size() == 32 || raw.size() == 24 || raw.size() < 32) return result;
    return result.substr(0, 64);
}

int sanitize_module_size(int size, const string& mod_id) {
    if (size <= 0) return 0;
    if (!mod_id.empty() && to_string(size) == mod_id) return 0;
    if (size > 200000000) return 0;
    return size;
}

static vector<uint8_t> extract_balanced_json_object(const vector<uint8_t>& data, size_t start) {
    if (start >= data.size() || data[start] != '{') return {};
    int depth = 0;
    vector<uint8_t> out;
    for (size_t i = start; i < data.size(); i++) {
        out.push_back(data[i]);
        if (data[i] == '{') depth++;
        else if (data[i] == '}') {
            depth--;
            if (depth == 0) return out;
        }
    }
    return {};
}

TaskCatalog scan_binary_associations(const vector<uint8_t>& data) {
    TaskCatalog cat;
    if (data.empty()) return cat;

    vector<pair<size_t, string>> task_positions;
    string data_str(reinterpret_cast<const char*>(data.data()), data.size());
    auto begin = sregex_iterator(data_str.begin(), data_str.end(), TASK_ID_RE);
    auto end = sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        size_t pos = static_cast<size_t>(it->position());
        task_positions.emplace_back(pos, it->str());
    }

    vector<pair<size_t, string>> cdn_hits;
    auto cdn_begin = sregex_iterator(data_str.begin(), data_str.end(), CDN_PATH_RE);
    for (auto it = cdn_begin; it != end; ++it) {
        size_t pos = static_cast<size_t>(it->position());
        cdn_hits.emplace_back(pos, sanitize_cdn_path(it->str()));
    }

    for (const auto& [tpos, tid] : task_positions) {
        auto& ent = cat.entries[tid];
        ent.task_id = tid;
        ent.source = "scan";

        string best_cdn;
        size_t best_dist = 10000000;
        for (const auto& [cpos, cpath] : cdn_hits) {
            size_t dist = (cpos > tpos) ? cpos - tpos : tpos - cpos;
            if (dist < best_dist && dist < 8000) {
                best_dist = dist;
                best_cdn = cpath;
            }
        }
        if (!best_cdn.empty()) {
            ent.cdn_path = best_cdn;
            ent.cdn_mod_id = mod_id_from_cdn(best_cdn);
        }
    }

    size_t pos = 0;
    while (pos < data.size()) {
        auto it = std::search(data.begin() + pos, data.end(), JSON_EXCLUDE_MARK.begin(), JSON_EXCLUDE_MARK.end());
        if (it == data.end()) break;
        pos = distance(data.begin(), it) + 1;
        auto raw = extract_balanced_json_object(data, pos - 1);
        if (raw.size() < 20) continue;

        string nearest_tid;
        size_t nearest_dist = 10000000;
        for (const auto& [tpos, tid] : task_positions) {
            if (tpos <= pos - 1) {
                size_t dist = (pos - 1) - tpos;
                if (dist < nearest_dist && dist < 12000) {
                    nearest_dist = dist;
                    nearest_tid = tid;
                }
            }
        }
        if (!nearest_tid.empty()) {
            auto& ent = cat.entries[nearest_tid];
            if (ent.task_id.empty()) ent.task_id = nearest_tid;
            ent.source = "scan";
            if (ent.template_json.empty()) ent.template_json = raw;
        }
    }

    return cat;
}

TaskCatalog catalog_from_parsed(const HbParseResult& parsed) {
    TaskCatalog cat;

    for (const auto& t : parsed.tasks) {
        if (!t.module_task.has_value()) continue;
        auto& mtd = t.module_task.value();
        string tid = mtd.id_str;
        if (!looks_like_vanguard_task_id_hex(tid)) continue;

        TaskCatalogEntry ent;
        ent.task_id = tid;
        ent.cdn_path = mtd.cdn_url;
        ent.task_type = mtd.task_type;
        ent.template_json = mtd.extra_raw;
        ent.source = "parsed";

        if (mtd.module.has_value() && !mtd.module->cdn_url.empty()) ent.cdn_path = mtd.module->cdn_url;
        if (mtd.module.has_value() && !mtd.module->module_id.empty()) {
            string name = mtd.module->module_id;
            while (!name.empty() && name.front() == ' ') name = name.substr(1);
            while (!name.empty() && name.back() == ' ') name.pop_back();
            if (is_valid_gateway_module_name(name)) ent.module_name = name;
        }
        if (mtd.module.has_value() && !mtd.module->sha256.empty())
            ent.module_sha256_hex = sha256_hex_from_module_bytes(mtd.module->sha256);
        if (mtd.module.has_value() && mtd.module->size > 0)
            ent.module_size = sanitize_module_size(mtd.module->size, ent.cdn_mod_id);
        if (!ent.cdn_path.empty()) {
            ent.cdn_path = sanitize_cdn_path(ent.cdn_path);
            ent.cdn_mod_id = mod_id_from_cdn(ent.cdn_path);
        }
        if (!mtd.extra_raw.empty() && ent.template_json.empty()) ent.template_json = mtd.extra_raw;

        auto cur_it = cat.entries.find(tid);
        if (cur_it == cat.entries.end()) {
            cat.entries[tid] = ent;
        } else {
            auto& cur = cur_it->second;
            if (!ent.module_name.empty() && cur.module_name.empty() && is_valid_gateway_module_name(ent.module_name))
                cur.module_name = ent.module_name;
            if (!ent.module_sha256_hex.empty() && cur.module_sha256_hex.empty())
                cur.module_sha256_hex = ent.module_sha256_hex;
            if (ent.module_size > 0 && cur.module_size == 0)
                cur.module_size = ent.module_size;
            if (!ent.cdn_path.empty() && (cur.cdn_path.empty() || mod_id_from_cdn(ent.cdn_path) == mod_id_from_cdn(cur.cdn_path))) {
                cur.cdn_path = ent.cdn_path;
                cur.cdn_mod_id = ent.cdn_mod_id;
            }
            if (ent.task_type.has_value() && !cur.task_type.has_value())
                cur.task_type = ent.task_type;
            if (!ent.template_json.empty() && cur.template_json.empty())
                cur.template_json = ent.template_json;
        }
    }

    for (const auto& tid : parsed.active_task_strings) {
        if (!looks_like_vanguard_task_id_hex(tid)) continue;
        if (cat.entries.find(tid) == cat.entries.end()) {
            TaskCatalogEntry ent;
            ent.task_id = tid;
            ent.source = "active";
            cat.entries[tid] = ent;
        }
    }

    for (const auto& url : parsed.cdn_urls) {
        string clean = sanitize_cdn_path(url);
        string mod_id = mod_id_from_cdn(clean);
        if (mod_id.empty()) continue;
        for (auto& [tid, ent] : cat.entries) {
            bool same = (ent.cdn_mod_id == mod_id) || (mod_id_from_cdn(ent.cdn_path) == mod_id);
            if (same && !ent.cdn_path.empty()) {
                ent.cdn_path = clean;
                ent.cdn_mod_id = mod_id;
            } else if (ent.cdn_path.empty()) {
                ent.cdn_path = clean;
                ent.cdn_mod_id = mod_id;
            }
        }
    }

    return cat;
}

TaskCatalog catalog_from_plain(const vector<uint8_t>& plain, int env_type) {
    auto parsed = parse_hb_plain(plain, env_type);
    auto cat = catalog_from_parsed(parsed);
    cat.merge(scan_binary_associations(plain));
    return cat;
}

TaskCatalog catalog_from_paths(const vector<fs::path>& paths) {
    TaskCatalog merged;
    for (const auto& path : paths) {
        if (!fs::exists(path)) continue;
        if (path.extension() != ".bin") continue;
        FILE* f = fopen(path.string().c_str(), "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        vector<uint8_t> plain(size);
        fread(plain.data(), 1, size, f);
        fclose(f);
        merged.merge(catalog_from_plain(plain));
    }
    return merged;
}

void TaskCatalog::merge(const TaskCatalog& other) {
    for (const auto& [tid, ent] : other.entries) {
        auto cur_it = entries.find(tid);
        if (cur_it == entries.end()) {
            entries[tid] = ent;
            continue;
        }
        auto& cur = cur_it->second;
        if (!ent.cdn_path.empty()) {
            bool same_mod = (!cur.cdn_mod_id.empty() && !ent.cdn_mod_id.empty() && cur.cdn_mod_id == ent.cdn_mod_id) ||
                (mod_id_from_cdn(cur.cdn_path) == mod_id_from_cdn(ent.cdn_path) && !mod_id_from_cdn(ent.cdn_path).empty());
            if (cur.cdn_path.empty() || (same_mod && !ent.cdn_path.empty())) {
                cur.cdn_path = ent.cdn_path;
                cur.cdn_mod_id = ent.cdn_mod_id.empty() ? mod_id_from_cdn(ent.cdn_path) : ent.cdn_mod_id;
            }
        }
        if (!ent.template_json.empty() && cur.template_json.empty())
            cur.template_json = ent.template_json;
        if (!ent.module_name.empty() && cur.module_name.empty() && is_valid_gateway_module_name(ent.module_name))
            cur.module_name = ent.module_name;
        if (!ent.module_sha256_hex.empty() && cur.module_sha256_hex.empty())
            cur.module_sha256_hex = ent.module_sha256_hex;
        if (ent.module_size > 0 && cur.module_size == 0)
            cur.module_size = ent.module_size;
        if (ent.task_type.has_value() && !cur.task_type.has_value())
            cur.task_type = ent.task_type;
        if (!ent.source.empty()) cur.source = cur.source;
    }
}

string catalog_to_json(const TaskCatalog& cat) {
    string json = "[";
    bool first = true;
    vector<string> sorted_ids;
    for (const auto& [tid, ent] : cat.entries) sorted_ids.push_back(tid);
    sort(sorted_ids.begin(), sorted_ids.end());
    for (const auto& tid : sorted_ids) {
        const auto& e = cat.entries.at(tid);
        if (!first) json += ",";
        first = false;
        json += "{\"task_id\":\"" + tid + "\",";
        json += "\"cdn_path\":\"" + e.cdn_path + "\",";
        json += "\"cdn_mod_id\":\"" + e.cdn_mod_id + "\",";
        json += "\"task_type\":" + (e.task_type.has_value() ? to_string(e.task_type.value()) : "null") + ",";
        json += "\"template_len\":" + to_string(e.template_json.size()) + ",";
        json += "\"has_template\":" + string(e.template_json.empty() ? "false" : "true") + ",";
        json += "\"source\":\"" + e.source + "\"}";
    }
    json += "]";
    return json;
}

vector<fs::path> default_hb_search_dirs() {
    vector<fs::path> dirs;
    fs::path root = fs::current_path().parent_path().parent_path();
    fs::path client = root.parent_path() / "client" / "launcher" / "bin" / "Release";
    dirs.push_back(root / "logs" / "hb_plain");
    dirs.push_back(client / "HB-plain");
    dirs.push_back(client / "HB-logs");
    vector<fs::path> result;
    for (const auto& d : dirs) {
        if (fs::exists(d)) result.push_back(d);
    }
    return result;
}
