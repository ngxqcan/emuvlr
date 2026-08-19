#include "task_analysis.hpp"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>

using namespace std;

static unordered_map<string, int> hb_dump_count;


void refresh_latest_cdn(TaskProbeQueue& queue, const vector<string>& urls) {
    for (const auto& raw : urls) {
        string clean = sanitize_cdn_path(raw);
        if (clean.empty()) continue;
        size_t pos = clean.find("/v1/cdn/mod/");
        if (pos == string::npos) continue;
        string mod_id = clean.substr(pos + 13);
        size_t q = mod_id.find('?');
        if (q != string::npos) mod_id = mod_id.substr(0, q);

        auto it = queue.latest_cdn_by_mod.find(mod_id);
        if (it == queue.latest_cdn_by_mod.end()) {
            queue.latest_cdn_by_mod[mod_id] = clean;
        }
    }
}

fs::path task_payload_log_dir() {
    fs::path d = fs::current_path().parent_path().parent_path() / "logs" / "task_payloads";
    fs::create_directories(d);
    return d;
}

void persist_task_payload_sample(const string& session_id, const string& task_id, const vector<uint8_t>& payload) {
    if (payload.empty() || task_id.empty()) return;
    string sid = session_id.substr(0, 8);
    string tid = task_id.substr(0, 24);
    fs::path path = task_payload_log_dir() / (sid + "_" + tid + ".bin");
    if (fs::exists(path)) return;

    FILE* f = fopen(path.string().c_str(), "wb");
    if (f) {
        fwrite(payload.data(), 1, payload.size(), f);
        fclose(f);
    }

    string head = payload_head_preview(payload, 160);
}

fs::path cdn_log_dir() {
    fs::path d = fs::current_path().parent_path().parent_path() / "logs" / "modules_cdn";
    fs::create_directories(d);
    return d;
}

void persist_cdn_urls(const string& session_id, const vector<string>& urls) {
    if (urls.empty()) return;
    fs::path path = cdn_log_dir() / (session_id.substr(0, 8) + "_cdn.txt");

    unordered_set<string> existing;
    if (fs::exists(path)) {
        FILE* f = fopen(path.string().c_str(), "r");
        if (f) {
            char line[1024];
            while (fgets(line, sizeof(line), f)) {
                string s(line);
                while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
                if (!s.empty()) existing.insert(s);
            }
            fclose(f);
        }
    }

    vector<string> new_urls;
    for (const auto& u : urls) {
        string clean = sanitize_cdn_path(u);
        if (!clean.empty() && !existing.count(clean)) {
            bool found = false;
            for (const auto& n : new_urls) {
                if (n == clean) { found = true; break; }
            }
            if (!found) new_urls.push_back(clean);
        }
    }

    if (new_urls.empty()) return;

    FILE* f = fopen(path.string().c_str(), "a");
    if (f) {
        for (const auto& u : new_urls) {
            fwrite(u.c_str(), 1, u.size(), f);
            fputc('\n', f);
        }
        fclose(f);
    }
}

fs::path catalog_log_dir() {
    fs::path d = fs::current_path().parent_path().parent_path() / "logs" / "task_catalog";
    fs::create_directories(d);
    return d;
}

void persist_task_catalog(const string& session_id, const TaskCatalog& catalog) {
    if (catalog.entries.empty()) return;
    fs::path path = catalog_log_dir() / (session_id.substr(0, 8) + "_catalog.json");
    string json = catalog_to_json(catalog);
    FILE* f = fopen(path.string().c_str(), "w");
    if (f) {
        fwrite(json.c_str(), 1, json.size(), f);
        fclose(f);
    }
}

void seed_catalog_from_disk(TaskProbeQueue& queue) {
    vector<fs::path> paths;
    for (const auto& d : default_hb_search_dirs()) {
        if (!fs::exists(d)) continue;
        for (const auto& entry : fs::directory_iterator(d)) {
            string name = entry.path().filename().string();
            if (name.find("_env8_hit.bin") != string::npos || name.find("_pc.bin") != string::npos) {
                paths.push_back(entry.path());
            }
        }
    }
    if (paths.empty()) return;
    sort(paths.begin(), paths.end());
}

int enqueue_baseline_probes(TaskProbeQueue& queue, const string& access_token,
    const vector<uint8_t>& session_aes, const vector<uint8_t>& server_rsa_pub,
    const vector<int>& active_ids) {
    if (!queue.baseline_done) {
        seed_catalog_from_disk(queue);
    }
    queue.baseline_done = true;
    return 0;
}

vector<string> pick_next_task_ids(const HbParseResult& parsed, TaskProbeQueue& queue) {
    if (static_cast<int>(queue.pending.size()) >= PROBE_QUEUE_PRESSURE) return {};

    vector<string> candidates;
    unordered_set<string> seen;

    auto add = [&](const string& tid) {
        if (looks_like_vanguard_task_id_hex(tid) &&
            !queue.acked_task_ids.count(tid) &&
            !seen.count(tid)) {
            seen.insert(tid);
            candidates.push_back(tid);
        }
    };

    for (const auto& s : parsed.active_task_strings) add(s);
    for (const auto& t : parsed.tasks) {
        if (!t.module_task.has_value()) continue;
        auto& mtd = t.module_task.value();
        if (mtd.id_str.empty()) continue;
        add(mtd.id_str);
    }
    auto targets = collect_real_task_targets(parsed);
    for (const auto& t : targets) {
        auto it = t.attrs.find("id_str");
        if (it != t.attrs.end() && !it->second.empty()) add(it->second);
    }

    if (candidates.size() > MAX_TASKS_PER_HB_INGEST)
        candidates.resize(MAX_TASKS_PER_HB_INGEST);
    return candidates;
}

double probe_interval_sec(const TaskProbeQueue& queue) {
    if (static_cast<int>(queue.pending.size()) >= PROBE_QUEUE_PRESSURE)
        return TASK_PROBE_INTERVAL_BUSY_SEC;
    return TASK_PROBE_INTERVAL_SEC;
}

int evict_defer_probes(TaskProbeQueue& queue, int count) {
    int removed = 0;
    size_t i = 0;
    while (i < queue.pending.size() && removed < count) {
        auto& item = queue.pending[i];
        if (!item.defer_wire) { i++; continue; }
        string tid = item.task_id;
        int attempts = item.defer_attempts;
        if (attempts >= 2 || skip_orphan_defer(queue, item)) {
            queue.pending.erase(queue.pending.begin() + i);
            queue.seen_keys.erase(item.key);
            removed++;
            continue;
        }
        i++;
    }
    return removed;
}

void make_room_in_probe_queue(TaskProbeQueue& queue, int need) {
    if (queue.pending.size() + need <= MAX_PROBE_QUEUE) return;
    int freed = evict_defer_probes(queue, max(need, 4));
}

string module_name_for_task(TaskProbeQueue& queue, const string& task_id) {
    auto it = queue.catalog.entries.find(task_id);
    if (it == queue.catalog.entries.end()) return "";
    string name = it->second.module_name;
    while (!name.empty() && (name.front() == ' ' || name.front() == '\t')) name.erase(name.begin());
    while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.pop_back();
    return is_valid_gateway_module_name(name) ? name : "";
}

string module_name_for_mod_id(TaskProbeQueue& queue, const string& mod_id) {
    if (mod_id.empty()) return "";
    string best;
    for (const auto& [tid, ent] : queue.catalog.entries) {
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

string cdn_path_for_task(TaskProbeQueue& queue, const string& task_id) {
    auto it = queue.catalog.entries.find(task_id);
    if (it == queue.catalog.entries.end()) return "";
    string mod_id = it->second.cdn_mod_id;
    string cdn_path = it->second.cdn_path;

    if (mod_id.empty() && !cdn_path.empty()) {
        size_t pos = cdn_path.find("/v1/cdn/mod/");
        if (pos != string::npos) {
            mod_id = cdn_path.substr(pos + 13);
            size_t q = mod_id.find('?');
            if (q != string::npos) mod_id = mod_id.substr(0, q);
        }
    }

    auto latest = queue.latest_cdn_by_mod.find(mod_id);
    if (latest != queue.latest_cdn_by_mod.end()) return latest->second;
    return cdn_path;
}

bool enqueue_defer_task_probe(TaskProbeQueue& queue, const string& task_id, bool prepend) {
    if (task_id.empty() || queue.acked_task_ids.count(task_id)) return false;

    string cdn_path = cdn_path_for_task(queue, task_id);
    string key = "task:" + task_id.substr(0, 24) + ":cdn_wait";

    if (queue.seen_keys.count(key)) {
        for (const auto& item : queue.pending) {
            if (item.task_id == task_id && item.defer_wire) return false;
        }
    } else {
        queue.seen_keys.insert(key);
    }

    ProbeQueueItem item;
    item.key = key;
    item.kind = "task";
    item.task_id = task_id;
    item.cdn_path = cdn_path;
    item.module_name = module_name_for_task(queue, task_id);
    item.defer_wire = true;

    if (static_cast<int>(queue.pending.size()) >= MAX_PROBE_QUEUE)
        make_room_in_probe_queue(queue, 1);
    if (static_cast<int>(queue.pending.size()) >= MAX_PROBE_QUEUE) return false;

    if (prepend) queue.pending.insert(queue.pending.begin(), item);
    else queue.pending.push_back(item);
    return true;
}

int flush_tasks_for_cdn_path(TaskProbeQueue& queue, const string& cdn_path,
    const string& session_id, const string& access_token,
    const vector<uint8_t>& session_aes, const vector<uint8_t>& server_rsa_pub) {
    string clean = sanitize_cdn_path(cdn_path);
    if (clean.empty()) return 0;

    if (static_cast<int>(queue.pending.size()) >= MAX_PROBE_QUEUE)
        make_room_in_probe_queue(queue, MAX_FLUSH_PER_CDN);
    if (static_cast<int>(queue.pending.size()) >= MAX_PROBE_QUEUE) return 0;

    size_t pos = clean.find("/v1/cdn/mod/");
    string mod_id;
    if (pos != string::npos) {
        mod_id = clean.substr(pos + 13);
        size_t q = mod_id.find('?');
        if (q != string::npos) mod_id = mod_id.substr(0, q);
    }

    int added = 0;
    unordered_set<string> pending_ids;
    for (const auto& i : queue.pending) pending_ids.insert(i.task_id);

    for (const auto& [tid, ent] : queue.catalog.entries) {
        if (added >= MAX_FLUSH_PER_CDN) break;
        if (static_cast<int>(queue.pending.size()) >= MAX_PROBE_QUEUE) break;
        if (queue.acked_task_ids.count(tid) || pending_ids.count(tid)) continue;

        string ent_cdn = sanitize_cdn_path(ent.cdn_path);
        string ent_mod = ent.cdn_mod_id;
        if (ent_mod.empty() && !ent_cdn.empty()) {
            size_t p = ent_cdn.find("/v1/cdn/mod/");
            if (p != string::npos) {
                ent_mod = ent_cdn.substr(p + 13);
                size_t q = ent_mod.find('?');
                if (q != string::npos) ent_mod = ent_mod.substr(0, q);
            }
        }

        if (ent_cdn != clean && ent_mod != mod_id) continue;

        if (enqueue_defer_task_probe(queue, tid, false)) {
            added++;
            pending_ids.insert(tid);
        }
    }
    return added;
}

void requeue_failed_task_probe(TaskProbeQueue& queue, const ProbeQueueItem& probe, int http_status) {
    if (!TASK_RETRY_ON_FAIL) return;
    if (http_status == 200 || http_status == 401 || http_status == 403 || http_status == 429) return;

    string tid = !probe.task_id.empty() ? probe.task_id : (probe.meta.count("task_id") ? probe.meta.at("task_id") : "");
    if (!looks_like_vanguard_task_id_hex(tid) || queue.acked_task_ids.count(tid)) return;

    queue.seen_keys.erase(probe.label);
    queue.probe_backoff_until = static_cast<double>(time(nullptr)) + TASK_RETRY_BACKOFF_SEC;
    enqueue_defer_task_probe(queue, tid, false);
}

optional<ProbeQueueItem> pop_defer_probe(TaskProbeQueue& queue) {
    if (!queue.pending.empty() && queue.pending.front().defer_wire) {
        auto item = queue.pending.front();
        queue.pending.erase(queue.pending.begin());
        return item;
    }
    return nullopt;
}

optional<ProbeQueueItem> materialize_task_probe(
    TaskProbeQueue& queue, const ProbeQueueItem& item,
    const string& access_token, const vector<uint8_t>& session_aes,
    const vector<uint8_t>& server_rsa_pub) {
    string tid = item.task_id;
    if (tid.empty()) return nullopt;

    auto payload = build_task_payload(tid, queue.catalog, queue.payload_cache, queue.region, queue.gw_cookies);
    if (payload.empty() || payload.size() < 4) return nullopt;

    TaskTarget target;
    target.label = tid.substr(0, 16);
    target.id_str = tid;

    auto atom = build_single_task_probe(access_token, session_aes, server_rsa_pub, target, payload);

    ProbeQueueItem result;
    result.key = atom.key;
    result.kind = atom.kind;
    result.wire = atom.wire;
    result.label = atom.key;
    result.vg_type = atom.vg_type;
    result.relay_flags = atom.relay_flags;
    result.meta = atom.meta;
    result.task_id = tid;
    return result;
}

int enqueue_task_probes(TaskProbeQueue& queue, const string& session_id,
    const string& access_token, const vector<uint8_t>& session_aes,
    const vector<uint8_t>& server_rsa_pub, const vector<string>& task_ids) {
    if (task_ids.empty()) return 0;

    int added = 0;
    vector<TaskTarget> targets;
    vector<vector<uint8_t>> payloads;

    for (const auto& tid : task_ids) {
        string cdn_path = cdn_path_for_task(queue, tid);
        if (!cdn_path.empty() && !queue.payload_cache.has_module(cdn_path, queue.region)) {
            if (enqueue_defer_task_probe(queue, tid, false)) added++;
            continue;
        }

        auto payload = build_task_payload(tid, queue.catalog, queue.payload_cache, queue.region, queue.gw_cookies);
        if (payload.empty() || payload.size() < 4) continue;

        TaskTarget target;
        target.label = tid.substr(0, 16);
        target.id_str = tid;
        targets.push_back(target);
        payloads.push_back(payload);
        persist_task_payload_sample(session_id, tid, payload);
    }

    if (!targets.empty() && TASK_WIRE_ENABLED) {
        auto probes = build_deterministic_task_probes(access_token, session_aes, server_rsa_pub, targets, payloads);
        added += enqueue_atomic_probes(queue.pending, queue.seen_keys, probes, MAX_PROBE_QUEUE, false);
    }
    return added;
}

fs::path hb_dump_dir() {
    fs::path d = fs::current_path().parent_path().parent_path() / "logs" / "hb_plain";
    fs::create_directories(d);
    return d;
}

tuple<optional<fs::path>, vector<uint8_t>, string> persist_hb_dump(
    const string& session_id, int env_type, const vector<uint8_t>& plain,
    const HbParseResult& parsed, bool force) {
    string sid = session_id.substr(0, 8);
    int n = hb_dump_count[sid];

    bool interesting = !parsed.cdn_urls.empty() || !parsed.tasks.empty() ||
        !parsed.active_task_strings.empty() || !parsed.modules.empty() || plain.size() >= 32;

    if (!force && !interesting) return {nullopt, {}, ""};
    if (n >= HB_DUMP_MAX_PER_SESSION && !interesting) return {nullopt, {}, ""};

    time_t now = time(nullptr);
    tm* utc = gmtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%S", utc);

    string tag = interesting ? "hit" : "scan";
    string base = string(ts) + "_" + sid + "_env" + to_string(env_type) + "_" + tag;
    fs::path dump_dir = hb_dump_dir();
    fs::path bin_path = dump_dir / (base + ".bin");
    fs::path txt_path = dump_dir / (base + ".txt");

    string report = format_parse_report(parsed) + "\n\nhead_hex=" + hex_preview(plain, 128) + "\n";

    FILE* f = fopen(bin_path.string().c_str(), "wb");
    if (f) {
        fwrite(plain.data(), 1, plain.size(), f);
        fclose(f);
    }

    f = fopen(txt_path.string().c_str(), "w");
    if (f) {
        fwrite(report.c_str(), 1, report.size(), f);
        fclose(f);
    }

    hb_dump_count[sid] = n + 1;
    return {txt_path, plain, report};
}

tuple<HbParseResult, vector<uint8_t>, string> ingest_hb_response(
    TaskProbeQueue& queue, const string& session_id, int env_type,
    const vector<uint8_t>& plain, const string& access_token,
    const vector<uint8_t>& session_aes, const vector<uint8_t>& server_rsa_pub,
    const vector<int>& active_ids) {
    auto parsed = parse_hb_plain(plain, env_type);
    auto [dump_path, dump_bin, dump_txt] = persist_hb_dump(session_id, env_type, plain, parsed);

    queue.catalog.merge(catalog_from_plain(plain, env_type));
    persist_task_catalog(session_id, queue.catalog);

    vector<string> new_urls;
    for (const auto& u : parsed.cdn_urls) {
        bool found = false;
        for (const auto& existing : queue.cdn_urls) {
            if (existing == u) { found = true; break; }
        }
        if (!found) {
            queue.cdn_urls.push_back(u);
            new_urls.push_back(u);
        }
    }

    if (!parsed.cdn_urls.empty()) refresh_latest_cdn(queue, parsed.cdn_urls);
    if (!new_urls.empty()) persist_cdn_urls(session_id, new_urls);

    for (const auto& u : parsed.cdn_urls) {
        queue.payload_cache.get_module(u, queue.region, true);
    }

    int added = 0;
    if (TASK_ANALYSIS_ENABLED && !access_token.empty() && session_aes.size() == 32) {
        auto next_ids = pick_next_task_ids(parsed, queue);
        if (!next_ids.empty()) {
            added = enqueue_task_probes(queue, session_id, access_token, session_aes, server_rsa_pub, next_ids);
        }
    }

    return {parsed, dump_bin, dump_txt};
}

bool defer_probe_cdn_ready(const TaskProbeQueue& queue, const ProbeQueueItem& item) {
    string tid = item.task_id;
    string cdn_path = sanitize_cdn_path(item.cdn_path);
    if (cdn_path.empty() && !tid.empty()) cdn_path = cdn_path_for_task(const_cast<TaskProbeQueue&>(queue), tid);
    return !cdn_path.empty() && queue.payload_cache.has_module(cdn_path, queue.region);
}

bool has_ready_task_wire(const TaskProbeQueue& queue) {
    if (queue.pending.empty()) return false;
    const auto& head = queue.pending.front();
    if (!head.defer_wire) return true;
    return defer_probe_cdn_ready(queue, head);
}

bool skip_orphan_defer(const TaskProbeQueue& queue, const ProbeQueueItem& item) {
    string tid = item.task_id;
    string cdn_path = sanitize_cdn_path(item.cdn_path);
    if (cdn_path.empty() && !tid.empty()) cdn_path = cdn_path_for_task(const_cast<TaskProbeQueue&>(queue), tid);
    int attempts = item.defer_attempts;
    if (cdn_path.empty()) return true;
    if (attempts >= MAX_DEFER_CDN_ATTEMPTS && !defer_probe_cdn_ready(queue, item)) return true;
    return false;
}

optional<ProbeQueueItem> pop_next_probe(
    TaskProbeQueue& queue, const string& access_token,
    const vector<uint8_t>& session_aes, const vector<uint8_t>& server_rsa_pub,
    const vector<int>& active_ids) {
    if (!TASK_ANALYSIS_ENABLED) return nullopt;
    if (queue.pending.empty()) return nullopt;

    double now = static_cast<double>(time(nullptr));
    if (now < queue.probe_backoff_until) return nullopt;
    if (now - queue.last_probe_at < probe_interval_sec(queue)) return nullopt;

    auto item = queue.pending.front();
    queue.last_probe_at = now;

    if (item.defer_wire) {
        if (skip_orphan_defer(queue, item)) {
            queue.pending.erase(queue.pending.begin());
            return pop_next_probe(queue, access_token, session_aes, server_rsa_pub, active_ids);
        }
        if (defer_probe_cdn_ready(queue, item)) {
            auto wire = materialize_task_probe(queue, item, access_token, session_aes, server_rsa_pub);
            if (wire.has_value() && !wire->wire.empty()) {
                queue.pending.erase(queue.pending.begin());
                return wire;
            }
        }
        queue.pending.front().defer_attempts++;
        return nullopt;
    }

    queue.pending.erase(queue.pending.begin());
    return item;
}

void record_probe_result(TaskProbeQueue& queue, const string& session_id,
    const ProbeQueueItem& probe, int http_status, int resp_env) {
    string label = probe.label;
    string kind = probe.kind;

    if (http_status == 429) {
        queue.probe_backoff_until = static_cast<double>(time(nullptr)) + 120.0;
        return;
    }

    if (http_status == 401) {
        queue.probe_backoff_until = static_cast<double>(time(nullptr)) + PROBE_401_BACKOFF_SEC;
        return;
    }

    if (http_status == 200) {
        queue.winners.push_back(label);
        string tid = !probe.task_id.empty() ? probe.task_id : (probe.meta.count("task_id") ? probe.meta.at("task_id") : "");
        if (looks_like_vanguard_task_id_hex(tid)) queue.acked_task_ids.insert(tid);
    } else {
        requeue_failed_task_probe(queue, probe, http_status);
    }
}
