#include "task_result_variants.hpp"
#include <algorithm>

using namespace std;

void write_field_varint(vector<uint8_t>& buf, int field, uint64_t value) {
    uint64_t key = (static_cast<uint64_t>(field) << 3);
    while (key >= 0x80) {
        buf.push_back(static_cast<uint8_t>((key & 0x7F) | 0x80));
        key >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(key));

    while (value >= 0x80) {
        buf.push_back(static_cast<uint8_t>((value & 0x7F) | 0x80));
        value >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(value));
}

void write_field_str(vector<uint8_t>& buf, int field, const string& value) {
    uint64_t key = (static_cast<uint64_t>(field) << 3) | 2;
    while (key >= 0x80) {
        buf.push_back(static_cast<uint8_t>((key & 0x7F) | 0x80));
        key >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(key));

    uint64_t len = value.size();
    while (len >= 0x80) {
        buf.push_back(static_cast<uint8_t>((len & 0x7F) | 0x80));
        len >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(len));
    buf.insert(buf.end(), value.begin(), value.end());
}

void write_field_bytes(vector<uint8_t>& buf, int field, const vector<uint8_t>& value) {
    uint64_t key = (static_cast<uint64_t>(field) << 3) | 2;
    while (key >= 0x80) {
        buf.push_back(static_cast<uint8_t>((key & 0x7F) | 0x80));
        key >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(key));

    uint64_t len = value.size();
    while (len >= 0x80) {
        buf.push_back(static_cast<uint8_t>((len & 0x7F) | 0x80));
        len >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(len));
    buf.insert(buf.end(), value.begin(), value.end());
}

void write_task_field(vector<uint8_t>& buf, int field, const TaskTarget& target, const string& id_wire) {
    if (field != 1) return;
    if (id_wire == "varint" && target.id_uint.has_value()) {
        write_field_varint(buf, 1, target.id_uint.value());
    } else if (id_wire == "string" && !target.id_str.empty()) {
        write_field_str(buf, 1, target.id_str);
    } else if (id_wire == "string" && target.id_uint.has_value()) {
        write_field_str(buf, 1, to_string(target.id_uint.value()));
    } else if (id_wire == "bytes" && !target.id_str.empty()) {
        vector<uint8_t> raw(target.id_str.begin(), target.id_str.end());
        write_field_bytes(buf, 1, raw);
    } else if (target.id_uint.has_value()) {
        write_field_varint(buf, 1, target.id_uint.value());
    }
}

vector<uint8_t> encode_task_result_submessage(const TaskResultVariant& variant, const TaskTarget& target) {
    vector<uint8_t> buf;
    int64_t now = now_ms();

    for (int field : variant.field_order) {
        if (field == 1) {
            write_task_field(buf, 1, target, variant.id_wire);
        } else if (field == 2) {
            write_field_bytes(buf, 2, variant.data);
        } else if (field == 3) {
            if (variant.use_module_result_msg) {
                vector<uint8_t> payload = variant.data.empty() ?
                    vector<uint8_t>{0x7b,0x22,0x6d,0x63,0x22,0x3a,0x7b,0x22,0x30,0x22,0x3a,0x31,0x7d,0x7d} : variant.data;
                write_field_bytes(buf, 3, payload);
            } else if (variant.status) {
                write_field_varint(buf, 3, variant.status);
            }
        } else if (field == 4 && variant.start_time.has_value()) {
            write_field_varint(buf, 4, variant.start_time.value());
        } else if (field == 5 && variant.end_time.has_value()) {
            write_field_varint(buf, 5, variant.end_time.value());
        } else if (field == 6 && !variant.performance_sub.empty()) {
            write_field_bytes(buf, 6, variant.performance_sub);
        }
    }

    if (find(variant.field_order.begin(), variant.field_order.end(), 4) == variant.field_order.end() && variant.start_time.has_value()) {
        write_field_varint(buf, 4, variant.start_time.value());
    }
    if (find(variant.field_order.begin(), variant.field_order.end(), 5) == variant.field_order.end() && variant.end_time.has_value()) {
        write_field_varint(buf, 5, variant.end_time.value());
    }

    return buf;
}

vector<uint8_t> encode_task_result_request(const string& access_token, const vector<vector<uint8_t>>& results) {
    vector<uint8_t> buf;
    if (!access_token.empty()) {
        write_field_str(buf, 1, access_token);
    }
    for (const auto& sub : results) {
        write_field_bytes(buf, 2, sub);
    }
    return buf;
}

vector<VariantEntry> build_variant_matrix(const vector<TaskTarget>& targets, bool include_sentinel) {
    int64_t now = now_ms();

    const vector<uint8_t> sentinel_mc = {0x7b,0x22,0x6d,0x63,0x22,0x3a,0x7b,0x22,0x30,0x22,0x3a,0x31,0x7d,0x7d};

    vector<TaskResultVariant> base_variants = {
        {"std_empty", {1,2,3}, {}, 1, nullopt, nullopt, {}, "varint", false},
        {"std_mc", {1,2,3}, sentinel_mc, 1, nullopt, nullopt, {}, "varint", false},
        {"ida_456", {1,2,3,4,5,6}, sentinel_mc, 1, now - 500, now, {}, "varint", false},
        {"ida_56_only", {1,2,5,6}, sentinel_mc, 1, nullopt, now, {0x08,0x01}, "varint", false},
        {"order_321", {3,2,1}, sentinel_mc, 1, nullopt, nullopt, {}, "varint", false},
        {"order_213", {2,1,3}, sentinel_mc, 1, nullopt, nullopt, {}, "varint", false},
        {"id_string", {1,2,3}, sentinel_mc, 1, nullopt, nullopt, {}, "string", false},
        {"id_bytes", {1,2,3}, sentinel_mc, 1, nullopt, nullopt, {}, "bytes", false},
        {"mod_result_f3", {1,2,3}, sentinel_mc, 1, nullopt, nullopt, {}, "varint", true},
        {"status0_mc", {1,2,3}, sentinel_mc, 0, nullopt, nullopt, {}, "varint", false},
        {"status2_mc", {1,2,3}, sentinel_mc, 2, nullopt, nullopt, {}, "varint", false}
    };

    vector<TaskTarget> work_targets = targets;
    if (include_sentinel) {
        work_targets.push_back({"sentinel", 4201050284ULL, ""});
        work_targets.push_back({"sentinel_str", nullopt, "4201050284"});
    }

    vector<VariantEntry> out;
    for (const auto& tgt : work_targets) {
        for (const auto& var : base_variants) {
            string name = tgt.label + "__" + var.name;
            out.push_back({name, tgt, var});
        }
    }

    return out;
}

vector<TaskTarget> targets_from_parsed_dict(const vector<vector<pair<string, string>>>& items) {
    vector<TaskTarget> out;
    for (size_t i = 0; i < items.size(); i++) {
        string label = "t" + to_string(i);
        string sid, cdn;
        optional<uint64_t> uid;

        for (const auto& [k, v] : items[i]) {
            if (k == "kind") label = v;
            else if (k == "id_str") sid = v;
            else if (k == "cdn_url") cdn = v;
            else if (k == "id_uint") uid = stoull(v);
        }

        if (uid.has_value()) {
            out.push_back({label, uid, sid.empty() ? cdn : sid});
        } else if (!sid.empty()) {
            out.push_back({label, nullopt, sid});
        } else if (!cdn.empty()) {
            out.push_back({label, nullopt, cdn});
        }
    }
    return out;
}
