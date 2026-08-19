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
#include "hb_task_catalog.hpp"
#include "task_result_variants.hpp"
#include "task_payload_builder.hpp"
#include "task_probe_matrix.hpp"

static constexpr bool TASK_WIRE_ENABLED = true;
static constexpr bool TASK_ANALYSIS_ENABLED = true;
static constexpr bool TASK_RETRY_ON_FAIL = true;
static constexpr double TASK_RETRY_BACKOFF_SEC = 2.0;
static constexpr double TASK_PROBE_INTERVAL_SEC = 1.0;
static constexpr double TASK_PROBE_INTERVAL_BUSY_SEC = 0.5;
static constexpr int MAX_PROBE_QUEUE = 64;
static constexpr int PROBE_QUEUE_PRESSURE = 32;
static constexpr int PROBE_401_BACKOFF_SEC = 15;
static constexpr int MAX_TASKS_PER_HB_INGEST = 4;
static constexpr int HB_MIN_BEFORE_TASK_PROBES = 1;
static constexpr int MAX_DEFER_CDN_ATTEMPTS = 3;
static constexpr int MAX_FLUSH_PER_CDN = 4;
static constexpr int HB_DUMP_MAX_PER_SESSION = 80;

struct TaskProbeQueue {
    std::vector<ProbeQueueItem> pending;
    std::unordered_set<std::string> seen_keys;
    double last_probe_at = 0.0;
    double probe_backoff_until = 0.0;
    std::vector<std::string> winners;
    std::vector<std::string> cdn_urls;
    bool baseline_done = false;
    int phase = 1;
    TaskCatalog catalog;
    TaskPayloadCache payload_cache;
    std::unordered_set<std::string> acked_task_ids;
    std::string region = "la";
    std::string gw_cookies;
    std::unordered_map<std::string, std::string> latest_cdn_by_mod;
};

void refresh_latest_cdn(TaskProbeQueue& queue, const std::vector<std::string>& urls);

void seed_catalog_from_disk(TaskProbeQueue& queue);
int enqueue_baseline_probes(TaskProbeQueue& queue, const std::string& access_token,
    const std::vector<uint8_t>& session_aes, const std::vector<uint8_t>& server_rsa_pub,
    const std::vector<int>& active_ids);

std::vector<std::string> pick_next_task_ids(const HbParseResult& parsed, TaskProbeQueue& queue);
double probe_interval_sec(const TaskProbeQueue& queue);
int evict_defer_probes(TaskProbeQueue& queue, int count = 4);
void make_room_in_probe_queue(TaskProbeQueue& queue, int need = 2);

std::string module_name_for_task(TaskProbeQueue& queue, const std::string& task_id);
std::string module_name_for_mod_id(TaskProbeQueue& queue, const std::string& mod_id);
std::string cdn_path_for_task(TaskProbeQueue& queue, const std::string& task_id);

bool enqueue_defer_task_probe(TaskProbeQueue& queue, const std::string& task_id, bool prepend = false);
int flush_tasks_for_cdn_path(TaskProbeQueue& queue, const std::string& cdn_path,
    const std::string& session_id, const std::string& access_token,
    const std::vector<uint8_t>& session_aes, const std::vector<uint8_t>& server_rsa_pub);

void requeue_failed_task_probe(TaskProbeQueue& queue, const ProbeQueueItem& probe, int http_status);
std::optional<ProbeQueueItem> pop_defer_probe(TaskProbeQueue& queue);

std::optional<ProbeQueueItem> materialize_task_probe(
    TaskProbeQueue& queue, const ProbeQueueItem& item,
    const std::string& access_token, const std::vector<uint8_t>& session_aes,
    const std::vector<uint8_t>& server_rsa_pub);

int enqueue_task_probes(TaskProbeQueue& queue, const std::string& session_id,
    const std::string& access_token, const std::vector<uint8_t>& session_aes,
    const std::vector<uint8_t>& server_rsa_pub, const std::vector<std::string>& task_ids);

std::tuple<std::optional<fs::path>, std::vector<uint8_t>, std::string> persist_hb_dump(
    const std::string& session_id, int env_type, const std::vector<uint8_t>& plain,
    const HbParseResult& parsed, bool force = false);

std::tuple<HbParseResult, std::vector<uint8_t>, std::string> ingest_hb_response(
    TaskProbeQueue& queue, const std::string& session_id, int env_type,
    const std::vector<uint8_t>& plain, const std::string& access_token = "",
    const std::vector<uint8_t>& session_aes = {}, const std::vector<uint8_t>& server_rsa_pub = {},
    const std::vector<int>& active_ids = {});

bool defer_probe_cdn_ready(const TaskProbeQueue& queue, const ProbeQueueItem& item);
bool has_ready_task_wire(const TaskProbeQueue& queue);
bool skip_orphan_defer(const TaskProbeQueue& queue, const ProbeQueueItem& item);

std::optional<ProbeQueueItem> pop_next_probe(
    TaskProbeQueue& queue, const std::string& access_token,
    const std::vector<uint8_t>& session_aes, const std::vector<uint8_t>& server_rsa_pub,
    const std::vector<int>& active_ids);

void record_probe_result(TaskProbeQueue& queue, const std::string& session_id,
    const ProbeQueueItem& probe, int http_status, int resp_env = 0);
