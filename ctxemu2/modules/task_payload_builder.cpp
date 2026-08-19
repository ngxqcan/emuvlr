#include "task_payload_builder.hpp"
#include <cstring>
#include <cstdio>
#include <sstream>
#include "module_loader.hpp"

using namespace std;

ModuleLoader g_module_loader;

static const string PC_PREFIX = "6a499d4a816869";
static const string MOBILE_PREFIX = "6a499d358d6682";

string build_mc_sentinel_json() {
    return "{\"mc\":{\"0\":1}}";
}

string build_module_result_json() {
    return "{\"mr\":{\"s\":1}}";
}

string build_npt_survey_json() {
    return "{\"survey\":{\"status\":1}}";
}

string build_pc_task_json() {
    return "{\"pc\":{\"done\":1}}";
}

vector<uint8_t> encode_task_performance_submessage(uint64_t duration_ns) {
    vector<uint8_t> out;
    uint64_t val = duration_ns;
    while (val >= 0x80) {
        out.push_back(static_cast<uint8_t>((val & 0x7F) | 0x80));
        val >>= 7;
    }
    out.push_back(static_cast<uint8_t>(val));
    return out;
}

string module_name_for_task(TaskPayloadCache& cache, const TaskCatalog& catalog, const string& task_id) {
    auto it = catalog.entries.find(task_id);
    if (it == catalog.entries.end()) return "";
    string name = it->second.module_name;
    while (!name.empty() && (name.front() == ' ' || name.front() == '\t')) name.erase(name.begin());
    while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.pop_back();
    if (is_valid_gateway_module_name(name)) return name;
    return "";
}

string module_name_for_mod_id(TaskPayloadCache& cache, const TaskCatalog& catalog, const string& mod_id) {
    if (mod_id.empty()) return "";
    string best;
    for (const auto& [tid, ent] : catalog.entries) {
        string mid = ent.cdn_mod_id;
        if (mid.empty() && !ent.cdn_path.empty()) {
            size_t pos = ent.cdn_path.find("/v1/cdn/mod/");
            if (pos != string::npos) {
                mid = ent.cdn_path.substr(pos + 13);
                size_t q = mid.find('?');
                if (q != string::npos) mid = mid.substr(0, q);
            }
        }
        if (mid != mod_id) continue;

        string name = ent.module_name;
        while (!name.empty() && (name.front() == ' ' || name.front() == '\t')) name.erase(name.begin());
        while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.pop_back();
        if (!is_valid_gateway_module_name(name)) continue;
        if (name.size() > best.size()) best = name;
    }
    return best;
}

static int sanitized_module_size(const TaskCatalogEntry& ent, const ModuleBlob* blob) {
    string mod_id = ent.cdn_mod_id;
    int size = ent.module_size;
    if (blob && !blob->data.empty()) return static_cast<int>(blob->data.size());
    if (size <= 0) return 0;
    if (!mod_id.empty() && to_string(size) == mod_id) return 0;
    if (size > 200000000) return 0;
    return size;
}

static string normalize_template(const vector<uint8_t>& raw) {
    if (raw.empty()) return "";
    string text(reinterpret_cast<const char*>(raw.data()), raw.size());
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\n' || text.front() == '\r'))
        text.erase(text.begin());
    if (text.empty() || text[0] != '{') {
        size_t pos = text.find("{\"");
        if (pos == string::npos) return "";
        text = text.substr(pos);
    }
    if (text.find("\"exclude\"") != string::npos) return "";
    return text;
}

static bool is_module_task(const TaskCatalogEntry& ent, const string& cdn_clean) {
    if (!cdn_clean.empty()) return true;
    if (!ent.module_sha256_hex.empty()) return true;
    if (ent.task_type == 2) return true;
    return false;
}

static string _module_id_for_task(const TaskCatalogEntry& ent, const string& cdn_clean) {
    string name = ent.module_name;
    while (!name.empty() && (name.front() == ' ' || name.front() == '\t')) name.erase(name.begin());
    while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.pop_back();
    if (is_valid_gateway_module_name(name)) return name;

    string mod_id = ent.cdn_mod_id;
    if (!mod_id.empty()) return mod_id;
    if (!cdn_clean.empty()) {
        size_t pos = cdn_clean.find("/v1/cdn/mod/");
        if (pos != string::npos) {
            mod_id = cdn_clean.substr(pos + 13);
            size_t q = mod_id.find('?');
            if (q != string::npos) mod_id = mod_id.substr(0, q);
            return mod_id;
        }
    }
    return "0";
}

vector<uint8_t> build_task_payload(
    const string& task_id,
    const TaskCatalog& catalog,
    TaskPayloadCache& cache,
    const string& region,
    const string& gw_cookies
) {
    if (!gw_cookies.empty()) cache.set_gw_cookies(gw_cookies);

    TaskCatalogEntry ent;
    auto it = catalog.entries.find(task_id);
    if (it != catalog.entries.end()) ent = it->second;
    else ent.task_id = task_id;

    string cdn_clean = sanitize_cdn_path(ent.cdn_path);
    string mod_id = ent.cdn_mod_id;
    if (mod_id.empty() && !cdn_clean.empty()) {
        size_t pos = cdn_clean.find("/v1/cdn/mod/");
        if (pos != string::npos) {
            mod_id = cdn_clean.substr(pos + 13);
            size_t q = mod_id.find('?');
            if (q != string::npos) mod_id = mod_id.substr(0, q);
        }
    }

    bool pc_fetched = false;
    if (!cdn_clean.empty()) {
        if (cache.has_pc_fetched_mod(mod_id) || cache.has_module(cdn_clean, region))
            pc_fetched = true;
    }

    auto blob = cache.get_module(cdn_clean, region, false);

    if (is_module_task(ent, cdn_clean)) {
        if (blob) {
            // Verify SHA256
            if (!ent.module_sha256_hex.empty() && blob->sha256_hex != ent.module_sha256_hex) {
                fprintf(stderr, "[build_task_payload] SHA256 mismatch for %s. Expected: %s, Got: %s\n",
                    cdn_clean.c_str(), ent.module_sha256_hex.c_str(), blob->sha256_hex.c_str());
            } else {
                if (g_module_loader.load(blob->mod_id, blob->cache_path)) {
                    string tmpl = normalize_template(ent.template_json);
                    auto out = g_module_loader.execute(blob->mod_id, 
                                        reinterpret_cast<const uint8_t*>(tmpl.data()), 
                                        tmpl.size());
                    if (!out.empty()) {
                        return out;
                    }
                }
            }
        }
        
        if (cdn_clean.empty() || pc_fetched || blob) {
            mod_id = _module_id_for_task(ent, cdn_clean);
            string json = build_mc_sentinel_json();
            return vector<uint8_t>(json.begin(), json.end());
        }
    }

    string tmpl = normalize_template(ent.template_json);
    if (!tmpl.empty()) return vector<uint8_t>(tmpl.begin(), tmpl.end());

    if (task_id.substr(0, PC_PREFIX.size()) == PC_PREFIX) {
        string json = build_npt_survey_json();
        return vector<uint8_t>(json.begin(), json.end());
    }

    if (task_id.substr(0, MOBILE_PREFIX.size()) == MOBILE_PREFIX) {
        string json = build_npt_survey_json();
        return vector<uint8_t>(json.begin(), json.end());
    }

    if (ent.task_type == 1) {
        string json = build_pc_task_json();
        return vector<uint8_t>(json.begin(), json.end());
    }

    if (ent.task_type == 2) {
        string json = build_mc_sentinel_json();
        return vector<uint8_t>(json.begin(), json.end());
    }

    string json = build_npt_survey_json();
    return vector<uint8_t>(json.begin(), json.end());
}

pair<vector<uint8_t>, vector<uint8_t>> build_task_payload_with_perf(
    const string& task_id,
    const TaskCatalog& catalog,
    TaskPayloadCache& cache,
    const string& region
) {
    auto data = build_task_payload(task_id, catalog, cache, region, "");
    auto perf = encode_task_performance_submessage(80000000ULL);
    return {data, perf};
}
