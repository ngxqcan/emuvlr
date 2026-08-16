#pragma once

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>
#include <tuple>
#include <optional>

struct TaskTarget {
    std::string label;
    std::optional<uint64_t> id_uint;
    std::string id_str;
};

struct TaskResultVariant {
    std::string name;
    std::vector<int> field_order;
    std::vector<uint8_t> data;
    int status = 1;
    std::optional<int64_t> start_time;
    std::optional<int64_t> end_time;
    std::vector<uint8_t> performance_sub;
    std::string id_wire = "varint";
    bool use_module_result_msg = false;
};

inline int64_t now_ms() {
    return static_cast<int64_t>(std::time(nullptr)) * 1000;
}

void write_field_varint(std::vector<uint8_t>& buf, int field, uint64_t value);
void write_field_str(std::vector<uint8_t>& buf, int field, const std::string& value);
void write_field_bytes(std::vector<uint8_t>& buf, int field, const std::vector<uint8_t>& value);

void write_task_field(std::vector<uint8_t>& buf, int field, const TaskTarget& target, const std::string& id_wire);

std::vector<uint8_t> encode_task_result_submessage(const TaskResultVariant& variant, const TaskTarget& target);

std::vector<uint8_t> encode_task_result_request(const std::string& access_token, const std::vector<std::vector<uint8_t>>& results);

struct VariantEntry {
    std::string name;
    TaskTarget target;
    TaskResultVariant variant;
};

std::vector<VariantEntry> build_variant_matrix(const std::vector<TaskTarget>& targets, bool include_sentinel = true);

std::vector<TaskTarget> targets_from_parsed_dict(const std::vector<std::vector<std::pair<std::string, std::string>>>& items);
