#include "hb_parse.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>

using namespace std;

static const regex CDN_SHORT_RE("/v1/cdn/mod/\\d+\\?verify=[0-9A-Za-z%\\-\\._\\+/=]+", regex_constants::icase);
static const regex URL_RE("https?://[^\s\\x00\"'<>]+", regex_constants::icase);

uint64_t read_varint(const vector<uint8_t>& data, size_t& pos) {
    uint64_t result = 0;
    int shift = 0;
    while (pos < data.size()) {
        uint8_t b = data[pos++];
        result |= static_cast<uint64_t>(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    return result;
}

pair<uint64_t, size_t> read_varint_pair(const vector<uint8_t>& data, size_t pos) {
    uint64_t result = 0;
    int shift = 0;
    while (pos < data.size()) {
        uint8_t b = data[pos++];
        result |= static_cast<uint64_t>(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    return {result, pos};
}

string sanitize_cdn_path(const string& raw) {
    if (raw.empty()) return "";
    string result = raw;
    if (result.substr(0, 8) == "https://") result = result.substr(8);
    else if (result.substr(0, 7) == "http://") result = result.substr(7);
    while (!result.empty() && result.back() == '/') result.pop_back();
    return result;
}

string resolve_cdn_url(const string& path, const string& region) {
    if (path.empty()) return "";
    if (path.substr(0, 4) == "http") return path;
    string base = "https://cdn";
    if (region != "la") base += "-" + region;
    return base + ".gateway.net/" + path;
}

ModuleBlob download_module(const string& cdn_path, const string& region, const string& cookies) {
    ModuleBlob blob;
    return blob;
}

bool looks_like_module_name(const string& s) {
    if (s.size() < 8 || s.size() > 512) return false;
    if (s[0] == '{' || s[0] == '[') return false;
    if (s.find("/v1/cdn/") != string::npos) return false;
    if (s.find("://") != string::npos) return false;
    return true;
}

bool looks_like_vanguard_task_id_hex(const string& s) {
    if (s.size() != 24) return false;
    for (char c : s) {
        if (!isxdigit(c)) return false;
    }
    string low = s;
    for (auto& c : low) c = tolower(c);
    if (low.substr(0, 4) != "6a49" && low.substr(0, 4) != "6a4a") return false;
    return true;
}

bool looks_like_base64_blob(const string& s) {
    if (s.size() < 28 || s.size() > 256) return false;
    bool has_upper = false, has_lower = false;
    for (char c : s) {
        if (c >= 'A' && c <= 'Z') has_upper = true;
        if (c >= 'a' && c <= 'z') has_lower = true;
    }
    if (!has_upper || !has_lower) return false;
    for (char c : s) {
        if (isalnum(c) || c == '+' || c == '/' || c == '=' || c == '_' || c == '-') continue;
        return false;
    }
    return true;
}

bool looks_like_task_id_string(const string& s) {
    if (looks_like_vanguard_task_id_hex(s)) return true;
    if (looks_like_base64_blob(s)) return false;
    if (s.size() < 2 || s.size() > 512) return false;
    if (s.substr(0, 7) == "http://" || s.substr(0, 8) == "https://" ||
        s.find("/v1/cdn/mod/") != string::npos || s.find("/vanguard/v1/cdn/") != string::npos) return false;
    if (s.find(' ') != string::npos && s.size() > 64) return false;
    for (char c : s) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == ':') continue;
        return false;
    }
    return true;
}

bool looks_like_hb_response_root(const vector<uint8_t>& data) {
    if (data.empty()) return false;
    return data[0] == 0x08 || data[0] == 0x12 || data[0] == 0x18 || data[0] == 0x22;
}

bool is_mostly_printable(const vector<uint8_t>& data) {
    if (data.empty()) return false;
    int printable = 0;
    for (uint8_t c : data) {
        if (c == 0 || (c >= 0x20 && c <= 0x7E)) printable++;
    }
    return printable * 10 >= static_cast<int>(data.size()) * 8;
}

bool looks_like_url(const string& s) {
    return s.substr(0, 7) == "http://" || s.substr(0, 8) == "https://" ||
           s.find("/v1/cdn/mod/") != string::npos || s.find("/vanguard/v1/cdn/") != string::npos;
}

bool looks_like_unix_ms(uint64_t ts) {
    return ts >= 1000000000000ULL && ts <= 4000000000000ULL;
}

int strict_hb_response_score(const vector<uint8_t>& data) {
    if (data.size() < 4) return -1;
    if (data[0] != 0x08 && data[0] != 0x12 && data[0] != 0x18 && data[0] != 0x22) return -1;

    int score = 0;
    size_t pos = 0;
    bool saw_f1 = false;
    int fields = 0;

    while (pos < data.size() && fields < 8) {
        auto [tag, new_pos] = read_varint_pair(data, pos);
        pos = new_pos;
        if (!tag) break;
        int fld = static_cast<int>(tag >> 3);
        int wire = static_cast<int>(tag & 7);
        if (fld < 1 || fld > 7) return -1;

        if (wire == 0) {
            auto [val, np] = read_varint_pair(data, pos);
            pos = np;
            if (fld == 1) {
                saw_f1 = true;
                if (looks_like_unix_ms(val)) score += 80;
                else if (val < 1000000) score -= 40;
                else score += 10;
            } else if (fld == 3 && (val == 0 || val == 1)) {
                score += 5;
            } else {
                score += 2;
            }
        } else if (wire == 2) {
            auto [ln, np] = read_varint_pair(data, pos);
            pos = np;
            if (ln > 65536 || pos + ln > data.size()) return -1;
            if (fld == 2) score += 30;
            else if (fld == 4) score += 15;
            else score += 3;
            pos += ln;
        } else if (wire == 5) {
            if (pos + 4 > data.size()) return -1;
            pos += 4;
            score += 1;
        } else if (wire == 1) {
            if (pos + 8 > data.size()) return -1;
            pos += 8;
            score += 1;
        } else {
            return -1;
        }
        fields++;
    }

    if (!saw_f1) score -= 20;
    return score;
}

pair<vector<uint8_t>, int> find_heartbeat_protobuf_slice(const vector<uint8_t>& plain) {
    if (plain.empty() || plain.size() == 32) return {{}, 0};

    auto try_off = [&](int off) -> pair<vector<uint8_t>, int> {
        vector<uint8_t> sub(plain.begin() + off, plain.end());
        if (strict_hb_response_score(sub) >= 50) return {sub, off};
        return {{}, 0};
    };

    auto [s, off] = try_off(0);
    if (!s.empty()) return {s, off};
    if (plain.size() > 32) return try_off(32);
    return {{}, 0};
}

string summarize_protobuf_fields(const vector<uint8_t>& data, int max_fields) {
    vector<string> parts;
    size_t pos = 0;
    int count = 0;
    while (pos < data.size() && count < max_fields) {
        size_t tag_pos = pos;
        auto [tag, new_pos] = read_varint_pair(data, pos);
        pos = new_pos;
        if (!tag) break;
        int fld = static_cast<int>(tag >> 3);
        int wire = static_cast<int>(tag & 7);
        string entry = "f" + to_string(fld) + ":w" + to_string(wire) + "@" + to_string(tag_pos);
        if (wire == 2) {
            auto [ln, np] = read_varint_pair(data, pos);
            pos = np;
            entry += ":L" + to_string(ln);
            if (pos + ln > data.size()) {
                entry += "(trunc)";
                parts.push_back(entry);
                break;
            }
            pos += ln;
        } else if (wire == 0) {
            auto [val, np] = read_varint_pair(data, pos);
            pos = np;
        } else if (wire == 5) {
            pos += 4;
        } else if (wire == 1) {
            pos += 8;
        } else {
            break;
        }
        parts.push_back(entry);
        count++;
    }
    string result;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i > 0) result += ",";
        result += parts[i];
    }
    return result;
}

static void append_unique_str(vector<string>& items, const string& s) {
    if (s.empty()) return;
    for (const auto& item : items) {
        if (item == s) return;
    }
    items.push_back(s);
}

static string make_full_url(const string& path) {
    string clean = sanitize_cdn_path(path);
    if (clean.empty() || clean.substr(0, 13) != "/v1/cdn/mod/") return "";
    if (clean.size() > 256) return "";
    return "https://la.vg.ac.pvp.net:8443" + clean;
}

static void append_unique_url(HbParseResult& out, const string& url) {
    string full = make_full_url(url);
    if (full.empty()) return;
    append_unique_str(out.cdn_urls, full);
}

void scan_urls_in_blob(HbParseResult& out, const vector<uint8_t>& data) {
    if (data.empty() || data.size() > 65536) return;
    string raw(reinterpret_cast<const char*>(data.data()), data.size());
    auto begin = sregex_iterator(raw.begin(), raw.end(), CDN_SHORT_RE);
    auto end = sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        append_unique_url(out, it->str());
    }
}

ModuleRecord parse_module_submessage(const vector<uint8_t>& data) {
    ModuleRecord mod;
    size_t pos = 0;
    while (pos < data.size()) {
        auto [tag, new_pos] = read_varint_pair(data, pos);
        pos = new_pos;
        if (!tag) break;
        int fld = static_cast<int>(tag >> 3);
        int wire = static_cast<int>(tag & 7);
        if (wire == 2) {
            auto [ln, np] = read_varint_pair(data, pos);
            pos = np;
            vector<uint8_t> chunk(data.begin() + pos, data.begin() + min(pos + ln, data.size()));
            pos += ln;
            string s(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            if (fld == 1 && mod.module_id.empty()) mod.module_id = s;
            else if (fld == 2 && mod.cdn_url.empty()) {
                if (s.find("/v1/cdn/mod/") != string::npos) mod.cdn_url = sanitize_cdn_path(s);
                else mod.cdn_url = s;
            } else if (fld == 3) {
                mod.arguments.push_back(s);
            } else if (fld == 4 && mod.module_id.empty() && looks_like_module_name(s)) {
                mod.module_id = s;
            } else if (fld == 5 && (ln == 24 || ln == 32)) {
                mod.sha256 = chunk;
            }
        } else if (wire == 0) {
            auto [val, np] = read_varint_pair(data, pos);
            pos = np;
            if (fld == 5) mod.size = static_cast<int>(val);
            else if (fld == 6) mod.load_flags = static_cast<int>(val);
        } else if (wire == 1) pos += 8;
        else if (wire == 5) pos += 4;
        else break;
    }
    return mod;
}

ModuleTaskData parse_module_task_data(const vector<uint8_t>& data) {
    ModuleTaskData mtd;
    size_t pos = 0;
    while (pos < data.size()) {
        auto [tag, new_pos] = read_varint_pair(data, pos);
        pos = new_pos;
        if (!tag) break;
        int fld = static_cast<int>(tag >> 3);
        int wire = static_cast<int>(tag & 7);
        if (wire == 2) {
            auto [ln, np] = read_varint_pair(data, pos);
            pos = np;
            vector<uint8_t> chunk(data.begin() + pos, data.begin() + min(pos + ln, data.size()));
            pos += ln;
            string s(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            if (fld == 1) {
                mtd.id_str = s;
            } else if (fld == 2) {
                string st = s;
                while (!st.empty() && st[0] == ' ') st = st.substr(1);
                if (!st.empty() && (st[0] == '{' || st[0] == '[')) {
                    mtd.extra_raw = chunk;
                } else if (s.find("/v1/cdn/mod/") != string::npos && s.find("verify=") != string::npos) {
                    mtd.cdn_url = sanitize_cdn_path(s);
                } else if (s.size() >= 48 && s.find('/') == string::npos && s.find("://") == string::npos) {
                    if (!mtd.module.has_value()) mtd.module = ModuleRecord();
                    string trimmed = s;
                    while (!trimmed.empty() && trimmed.front() == ' ') trimmed = trimmed.substr(1);
                    while (!trimmed.empty() && trimmed.back() == ' ') trimmed.pop_back();
                    if (mtd.module->module_id.empty() || trimmed.size() > mtd.module->module_id.size())
                        mtd.module->module_id = trimmed;
                } else {
                    auto inner = parse_module_task_data(chunk);
                    if (inner.module.has_value()) mtd.module = inner.module;
                    if (!inner.cdn_url.empty()) mtd.cdn_url = inner.cdn_url;
                    if (inner.task_type.has_value()) mtd.task_type = inner.task_type;
                    if (!inner.extra_raw.empty()) mtd.extra_raw = inner.extra_raw;
                }
            } else if (fld == 3) {
                mtd.module = parse_module_submessage(chunk);
            } else if (fld == 4) {
                if (!mtd.module.has_value()) mtd.module = ModuleRecord();
                string trimmed = s;
                while (!trimmed.empty() && trimmed.front() == ' ') trimmed = trimmed.substr(1);
                while (!trimmed.empty() && trimmed.back() == ' ') trimmed.pop_back();
                if (looks_like_module_name(trimmed)) mtd.module->module_id = trimmed;
            } else if (fld == 5) {
                if (!mtd.module.has_value()) mtd.module = ModuleRecord();
                if (ln == 32 || ln == 24) mtd.module->sha256 = chunk;
            } else if (fld == 11) {
                if (looks_like_url(s) || s.find("/cdn/mod/") != string::npos) {
                    mtd.cdn_url = sanitize_cdn_path(s);
                }
            } else if (fld == 6) {
                mtd.extra_raw = chunk;
            }
        } else if (wire == 0) {
            auto [val, np] = read_varint_pair(data, pos);
            pos = np;
            if (fld == 2) mtd.task_type = static_cast<int>(val);
            else if (fld == 4) mtd.aux_type = static_cast<int>(val);
            else if (fld == 5) mtd.aux_type = static_cast<int>(val);
            else if (fld == 6) {
                if (!mtd.module.has_value()) mtd.module = ModuleRecord();
                mtd.module->size = static_cast<int>(val);
            }
        } else if (wire == 1) pos += 8;
        else if (wire == 5) pos += 4;
        else break;
    }
    return mtd;
}

optional<uint64_t> read_task_root_varint_id(const vector<uint8_t>& data) {
    if (data.size() < 2) return nullopt;
    if ((data[0] & 7) != 0 || (data[0] >> 3) != 1) return nullopt;
    size_t pos = 0;
    auto [tag, new_pos] = read_varint_pair(data, pos);
    pos = new_pos;
    if ((tag >> 3) != 1 || (tag & 7) != 0) return nullopt;
    auto [val, final_pos] = read_varint_pair(data, pos);
    if (val == 0 || val >= 0xFFFFFFFF) return nullopt;
    return val;
}

TaskRecord parse_task_submessage(const vector<uint8_t>& data) {
    TaskRecord task;
    size_t pos = 0;
    while (pos < data.size()) {
        auto [tag, new_pos] = read_varint_pair(data, pos);
        pos = new_pos;
        if (!tag) break;
        int fld = static_cast<int>(tag >> 3);
        int wire = static_cast<int>(tag & 7);
        if (wire == 0 && fld == 1) {
            auto [val, np] = read_varint_pair(data, pos);
            pos = np;
            if (val) task.id_uint = val;
        } else if (wire == 2) {
            auto [ln, np] = read_varint_pair(data, pos);
            pos = np;
            vector<uint8_t> chunk(data.begin() + pos, data.begin() + min(pos + ln, data.size()));
            pos += ln;
            if (fld == 1) {
                string s(reinterpret_cast<const char*>(chunk.data()), chunk.size());
                if (looks_like_task_id_string(s)) {
                    if (!task.module_task.has_value()) task.module_task = ModuleTaskData();
                    task.module_task->id_str = s;
                } else if (!s.empty() && all_of(s.begin(), s.end(), ::isdigit) && !task.id_uint.has_value()) {
                    try { task.id_uint = stoull(s); } catch (...) {}
                }
            } else if (fld == 2) {
                task.module_task = parse_module_task_data(chunk);
            } else if (fld == 9) {
                auto mtd = parse_module_task_data(chunk);
                if (task.module_task.has_value()) {
                    if (mtd.module.has_value() && !task.module_task->module.has_value())
                        task.module_task->module = mtd.module;
                    if (!mtd.cdn_url.empty() && task.module_task->cdn_url.empty())
                        task.module_task->cdn_url = mtd.cdn_url;
                    if (mtd.task_type.has_value() && !task.module_task->task_type.has_value())
                        task.module_task->task_type = mtd.task_type;
                } else {
                    task.module_task = mtd;
                }
            }
        } else if (wire == 0) {
            auto [val, np] = read_varint_pair(data, pos);
            pos = np;
        } else if (wire == 1) pos += 8;
        else if (wire == 5) pos += 4;
        else break;
    }
    return task;
}

static string task_dedup_key(const TaskRecord& t) {
    string key = t.id_uint.has_value() ? to_string(t.id_uint.value()) : "";
    if (t.module_task.has_value()) {
        auto& mtd = t.module_task.value();
        key += "|" + mtd.id_str + "|" + mtd.cdn_url;
        if (mtd.module.has_value()) {
            key += "|" + mtd.module->module_id + "|" + mtd.module->cdn_url;
        }
    }
    return key;
}

static void merge_task(HbParseResult& out, const TaskRecord& task, unordered_set<string>& seen) {
    if (!task.id_uint.has_value() && !task.module_task.has_value()) return;
    string key = task_dedup_key(task);
    if (seen.count(key)) return;
    seen.insert(key);
    out.tasks.push_back(task);
    if (task.module_task.has_value()) {
        auto& mtd = task.module_task.value();
        if (!mtd.cdn_url.empty()) append_unique_url(out, mtd.cdn_url);
        if (!mtd.id_str.empty()) append_unique_str(out.all_strings, mtd.id_str);
        if (mtd.module.has_value()) {
            out.modules.push_back(mtd.module.value());
            if (!mtd.module->cdn_url.empty()) append_unique_url(out, mtd.module->cdn_url);
            if (!mtd.module->module_id.empty()) append_unique_str(out.all_strings, mtd.module->module_id);
        }
    }
}

void collect_tasks_from_modules_response(const vector<uint8_t>& data, HbParseResult& out, unordered_set<string>& seen) {
    size_t pos = 0;
    while (pos < data.size()) {
        auto [tag, new_pos] = read_varint_pair(data, pos);
        pos = new_pos;
        if (!tag) break;
        int fld = static_cast<int>(tag >> 3);
        int wire = static_cast<int>(tag & 7);
        if (wire == 2 && fld == 1) {
            auto [ln, np] = read_varint_pair(data, pos);
            pos = np;
            vector<uint8_t> chunk(data.begin() + pos, data.begin() + min(pos + ln, data.size()));
            pos += ln;
            ModuleRecord mod = parse_module_submessage(chunk);
            if (!mod.module_id.empty() || !mod.cdn_url.empty()) out.modules.push_back(mod);
            if (!mod.cdn_url.empty()) append_unique_url(out, mod.cdn_url);
            if (!mod.module_id.empty()) append_unique_str(out.all_strings, mod.module_id);

            TaskRecord tr;
            tr.module_task = ModuleTaskData();
            tr.module_task->module = mod;
            tr.module_task->id_str = mod.module_id;
            tr.module_task->cdn_url = mod.cdn_url;
            merge_task(out, tr, seen);
        } else if (wire == 0) {
            auto [val, np] = read_varint_pair(data, pos);
            pos = np;
        } else if (wire == 2) {
            auto [ln, np] = read_varint_pair(data, pos);
            pos = np;
            pos += ln;
        } else if (wire == 1) pos += 8;
        else if (wire == 5) pos += 4;
        else break;
    }
}

void extract_nested_task_strings(const vector<uint8_t>& data, HbParseResult& out, int depth) {
    if (depth > 16 || data.empty() || data.size() > 65536) return;
    size_t pos = 0;
    while (pos < data.size()) {
        auto [tag, new_pos] = read_varint_pair(data, pos);
        pos = new_pos;
        if (!tag) break;
        int wire = static_cast<int>(tag & 7);
        if (wire == 2) {
            auto [ln, np] = read_varint_pair(data, pos);
            pos = np;
            vector<uint8_t> chunk(data.begin() + pos, data.begin() + min(pos + ln, data.size()));
            pos += ln;
            if (ln >= 2 && ln <= 512 && is_mostly_printable(chunk)) {
                string s(reinterpret_cast<const char*>(chunk.data()), chunk.size());
                if (looks_like_task_id_string(s)) {
                    append_unique_str(out.active_task_strings, s);
                    append_unique_str(out.all_strings, s);
                }
                if (looks_like_url(s)) append_unique_url(out, s);
            }
            extract_nested_task_strings(chunk, out, depth + 1);
            scan_urls_in_blob(out, chunk);
        } else if (wire == 0) {
            auto [val, np] = read_varint_pair(data, pos);
            pos = np;
        } else if (wire == 1) pos += 8;
        else if (wire == 5) pos += 4;
        else break;
    }
}

void deep_collect_tasks(const vector<uint8_t>& data, HbParseResult& out, unordered_set<string>& seen, int depth) {
    if (depth > 12 || data.empty() || data.size() > 65536) return;

    string f1_str;
    optional<uint64_t> f1_varint;
    size_t pos = 0;
    while (pos < data.size()) {
        auto [tag, new_pos] = read_varint_pair(data, pos);
        pos = new_pos;
        if (!tag) break;
        int fld = static_cast<int>(tag >> 3);
        int wire = static_cast<int>(tag & 7);
        if (wire == 0) {
            auto [val, np] = read_varint_pair(data, pos);
            pos = np;
            if (fld == 1 && val > 0 && val < 0xFFFFFFFF) f1_varint = val;
        } else if (wire == 2) {
            auto [ln, np] = read_varint_pair(data, pos);
            pos = np;
            vector<uint8_t> chunk(data.begin() + pos, data.begin() + min(pos + ln, data.size()));
            pos += ln;
            if (fld == 1 && ln > 0 && ln <= 4096) {
                string s(reinterpret_cast<const char*>(chunk.data()), chunk.size());
                if (!looks_like_url(s)) f1_str = s;
            }
            deep_collect_tasks(chunk, out, seen, depth + 1);
        } else if (wire == 1) pos += 8;
        else if (wire == 5) pos += 4;
        else break;
    }

    if (!f1_str.empty() && !looks_like_url(f1_str)) {
        if (looks_like_task_id_string(f1_str)) append_unique_str(out.active_task_strings, f1_str);
        append_unique_str(out.all_strings, f1_str);
        bool all_digits = !f1_str.empty() && all_of(f1_str.begin(), f1_str.end(), ::isdigit);
        if (all_digits) {
            try {
                TaskRecord tr;
                tr.id_uint = stoull(f1_str);
                merge_task(out, tr, seen);
            } catch (...) {}
        }
    }
    if (f1_varint.has_value()) {
        TaskRecord tr;
        tr.id_uint = f1_varint.value();
        merge_task(out, tr, seen);
    }
}

void parse_hb_field2_chunk(const vector<uint8_t>& data, HbParseResult& out, unordered_set<string>& seen) {
    if (data.empty()) return;
    size_t tasks_before = out.tasks.size();
    size_t strs_before = out.active_task_strings.size();

    collect_tasks_from_modules_response(data, out, seen);
    auto task = parse_task_submessage(data);
    merge_task(out, task, seen);
    auto mtd = parse_module_task_data(data);
    if (!mtd.id_str.empty() || !mtd.cdn_url.empty() || mtd.module.has_value()) {
        TaskRecord tr;
        tr.module_task = mtd;
        merge_task(out, tr, seen);
    }
    extract_nested_task_strings(data, out);
    deep_collect_tasks(data, out, seen);
    scan_urls_in_blob(out, data);

    if (out.tasks.size() == tasks_before && out.active_task_strings.size() == strs_before &&
        data.size() <= 512 && is_mostly_printable(data)) {
        string raw(reinterpret_cast<const char*>(data.data()), data.size());
        if (looks_like_task_id_string(raw)) append_unique_str(out.active_task_strings, raw);
    }
}

HbParseResult parse_hb_plain(const vector<uint8_t>& plain, int env_type) {
    HbParseResult out;
    out.env_type = env_type;
    out.plain_bytes = static_cast<int>(plain.size());
    scan_urls_in_blob(out, plain);

    if (env_type == VG_MODULES_RESP) {
        unordered_set<string> seen;
        collect_tasks_from_modules_response(plain, out, seen);
        out.field_summary = summarize_protobuf_fields(plain);
        out.slice_bytes = static_cast<int>(plain.size());
        return out;
    }

    auto [slice_data, offset] = find_heartbeat_protobuf_slice(plain);
    out.slice_offset = offset;
    out.slice_bytes = static_cast<int>(slice_data.size());
    if (!slice_data.empty()) scan_urls_in_blob(out, slice_data);

    unordered_set<string> seen;
    vector<uint8_t> data = slice_data.empty() ? plain : slice_data;
    out.field_summary = summarize_protobuf_fields(data);

    size_t pos = 0;
    while (pos < data.size()) {
        auto [tag, new_pos] = read_varint_pair(data, pos);
        pos = new_pos;
        if (!tag) break;
        int fld = static_cast<int>(tag >> 3);
        int wire = static_cast<int>(tag & 7);

        if (wire == 0) {
            auto [val, np] = read_varint_pair(data, pos);
            pos = np;
            if (fld == 1) out.timestamp = val;
            else if (fld == 3) out.should_disconnect = (val == 1);
        } else if (wire == 2) {
            auto [ln, np] = read_varint_pair(data, pos);
            pos = np;
            vector<uint8_t> chunk(data.begin() + pos, data.begin() + min(pos + ln, data.size()));
            pos += ln;
            if (fld == 2) {
                auto root_id = read_task_root_varint_id(chunk);
                if (root_id.has_value()) {
                    TaskRecord tr;
                    tr.id_uint = root_id.value();
                    merge_task(out, tr, seen);
                }
                parse_hb_field2_chunk(chunk, out, seen);
            } else if (fld == 1) {
                parse_hb_field2_chunk(chunk, out, seen);
            } else if (fld == 4 && ln > 0) {
                string s(reinterpret_cast<const char*>(chunk.data()), chunk.size());
                if (looks_like_task_id_string(s)) {
                    append_unique_str(out.active_task_strings, s);
                    append_unique_str(out.all_strings, s);
                }
            } else if (fld == 5 || fld == 6 || fld == 7) {
                extract_nested_task_strings(chunk, out);
            }
            scan_urls_in_blob(out, chunk);
        } else if (wire == 1) pos += 8;
        else if (wire == 5) pos += 4;
        else break;
    }

    return out;
}

vector<TargetEntry> collect_task_targets(const HbParseResult& parsed) {
    vector<TargetEntry> targets;
    unordered_set<string> seen;

    auto add = [&](const string& kind, const unordered_map<string, string>& attrs) {
        string key;
        for (const auto& [k, v] : attrs) key += k + "=" + v + ";";
        if (seen.count(key)) return;
        seen.insert(key);
        targets.push_back({kind, attrs});
    };

    for (const auto& t : parsed.tasks) {
        if (t.id_uint.has_value()) {
            add("task_uint", {{"id_uint", to_string(t.id_uint.value())}});
        }
        if (t.module_task.has_value()) {
            auto& mtd = t.module_task.value();
            if (!mtd.id_str.empty())
                add("module_task_id", {{"id_str", mtd.id_str}, {"task_type", mtd.task_type.has_value() ? to_string(mtd.task_type.value()) : ""}});
            if (!mtd.cdn_url.empty())
                add("cdn_only", {{"cdn_url", mtd.cdn_url}, {"id_str", mtd.id_str}});
            if (mtd.module.has_value() && !mtd.module->module_id.empty())
                add("nested_module", {{"id_str", mtd.module->module_id}, {"cdn_url", mtd.module->cdn_url}});
        }
    }

    for (const auto& s : parsed.active_task_strings) {
        add("active_task_str", {{"id_str", s}});
    }

    for (const auto& mod : parsed.modules) {
        if (!mod.module_id.empty() || !mod.cdn_url.empty()) {
            add("module_row", {{"id_str", mod.module_id}, {"cdn_url", mod.cdn_url}});
        }
    }

    for (const auto& url : parsed.cdn_urls) {
        add("cdn_url", {{"cdn_url", url}});
    }

    return targets;
}

vector<TargetEntry> collect_real_task_targets(const HbParseResult& parsed) {
    vector<TargetEntry> targets;
    unordered_set<string> seen;

    if (parsed.timestamp != 0 && !looks_like_unix_ms(parsed.timestamp)) return targets;

    if (!parsed.active_task_strings.empty()) {
        for (const auto& s : parsed.active_task_strings) {
            if (looks_like_task_id_string(s) && s.size() >= 8) {
                string key = "active:" + s;
                if (seen.count(key)) continue;
                seen.insert(key);
                targets.push_back({"active_task_str", {{"id_str", s}}});
            }
        }
        return targets;
    }

    return targets;
}

string format_parse_report(const HbParseResult& parsed) {
    stringstream ss;
    ss << "env_type=" << parsed.env_type << " ts=" << parsed.timestamp
       << " disconnect=" << parsed.should_disconnect << "\n";
    ss << "plain=" << parsed.plain_bytes << "B slice=" << parsed.slice_bytes
       << "B off=" << parsed.slice_offset << "\n";
    ss << "fields=[" << parsed.field_summary << "]\n";
    ss << "tasks=" << parsed.tasks.size() << " active_strings=" << parsed.active_task_strings.size()
       << " modules=" << parsed.modules.size() << " cdn_urls=" << parsed.cdn_urls.size() << "\n";

    for (size_t i = 0; i < parsed.cdn_urls.size(); i++)
        ss << "  CDN[" << i << "] " << parsed.cdn_urls[i].substr(0, 120) << "\n";

    for (size_t i = 0; i < parsed.tasks.size(); i++) {
        auto& t = parsed.tasks[i];
        ss << "  Task[" << i << "]";
        if (t.id_uint.has_value()) ss << " id_uint=" << t.id_uint.value();
        if (t.module_task.has_value()) {
            auto& mtd = t.module_task.value();
            if (!mtd.id_str.empty()) ss << " id_str=" << mtd.id_str.substr(0, 48);
            if (!mtd.cdn_url.empty()) ss << " cdn=" << mtd.cdn_url.substr(0, 200);
            if (mtd.task_type.has_value()) ss << " type=" << mtd.task_type.value();
            if (mtd.module.has_value() && !mtd.module->cdn_url.empty())
                ss << " mod_cdn=" << mtd.module->cdn_url.substr(0, 120);
        }
        ss << "\n";
    }

    for (size_t i = 0; i < parsed.modules.size(); i++)
        ss << "  Module[" << i << "] id=" << parsed.modules[i].module_id.substr(0, 48)
           << " cdn=" << parsed.modules[i].cdn_url.substr(0, 120) << "\n";

    for (size_t i = 0; i < parsed.active_task_strings.size() && i < 20; i++)
        ss << "  active[" << i << "] " << parsed.active_task_strings[i].substr(0, 80) << "\n";

    for (size_t i = 0; i < parsed.all_strings.size() && i < 30; i++) {
        bool is_active = false;
        for (const auto& a : parsed.active_task_strings) {
            if (a == parsed.all_strings[i]) { is_active = true; break; }
        }
        if (!is_active) ss << "  str[" << i << "] " << parsed.all_strings[i].substr(0, 80) << "\n";
    }

    return ss.str();
}

string hex_preview(const vector<uint8_t>& data, int max_bytes) {
    int n = min(static_cast<int>(data.size()), max_bytes);
    stringstream ss;
    for (int i = 0; i < n; i++) {
        if (i > 0) ss << " ";
        ss << hex << setw(2) << setfill('0') << static_cast<int>(data[i]);
    }
    if (static_cast<int>(data.size()) > n) ss << " ...";
    return ss.str();
}
